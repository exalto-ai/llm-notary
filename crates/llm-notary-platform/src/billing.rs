use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use sqlx::{FromRow, Postgres, Transaction};
use url::Url;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use super::{
    ApiError, ApiResult, AppState, BillingConfig, ErrorResponse, StripeConfig,
    authenticated_web_user, database_error,
    service_admission::{
        BillingStatus, PurchaseAdjustmentSpec, ServicePlan, apply_purchase_adjustment,
        grant_external_purchase, set_account_billing_state,
    },
    unix_timestamp,
};

const STRIPE_API_VERSION: &str = "2026-02-25.clover";
const BYTES_PER_GB: i64 = 1_000_000_000;
const CENTS_PER_GB: i64 = 500;
const BYTES_PER_CENT: i64 = BYTES_PER_GB / CENTS_PER_GB;
const MAX_QUANTITY_GB: i64 = 20;
const MAX_WEBHOOK_BYTES: usize = 1 << 20;
const WEBHOOK_TOLERANCE_SECS: i64 = 5 * 60;
const STRIPE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BillingPurchaseMode {
    Disabled,
    Test,
    Live,
}

#[derive(Clone)]
pub struct BillingService {
    stripe: Option<StripeClient>,
    app_url: Url,
}

impl BillingService {
    pub fn from_config(
        config: &BillingConfig,
        app_url: &Url,
        http: reqwest::Client,
    ) -> Result<Self> {
        let stripe = config
            .stripe
            .as_ref()
            .map(|config| {
                StripeClient::new(
                    http,
                    Url::parse("https://api.stripe.com/v1/")?,
                    config.clone(),
                    false,
                )
            })
            .transpose()?;
        Ok(Self {
            stripe,
            app_url: app_url.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn disabled_for_test() -> Self {
        Self {
            stripe: None,
            app_url: Url::parse("https://example.test").unwrap(),
        }
    }

    #[cfg(test)]
    fn for_test(api_base: Url, app_url: Url) -> Self {
        Self {
            stripe: Some(
                StripeClient::new(
                    reqwest::Client::new(),
                    api_base,
                    StripeConfig {
                        secret_key: "sk_test_fixture".to_owned(),
                        webhook_secret: "whsec_fixture_secret".to_owned(),
                        price_id: "price_fixture".to_owned(),
                        livemode: false,
                    },
                    true,
                )
                .unwrap(),
            ),
            app_url,
        }
    }

    fn stripe(&self) -> ApiResult<&StripeClient> {
        self.stripe.as_ref().ok_or_else(|| {
            ApiError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                "billing_unavailable",
                "Hosted credit purchases are not configured",
            )
        })
    }

    pub(crate) fn purchase_mode(&self) -> BillingPurchaseMode {
        match self.stripe.as_ref() {
            None => BillingPurchaseMode::Disabled,
            Some(stripe) if stripe.livemode => BillingPurchaseMode::Live,
            Some(_) => BillingPurchaseMode::Test,
        }
    }
}

#[derive(Clone)]
struct StripeClient {
    http: reqwest::Client,
    api_base: Url,
    secret_key: Arc<str>,
    webhook_secret: Arc<str>,
    price_id: Arc<str>,
    livemode: bool,
    allow_local_checkout_url: bool,
    request_timeout: Duration,
}

impl StripeClient {
    fn new(
        http: reqwest::Client,
        api_base: Url,
        config: StripeConfig,
        allow_local_checkout_url: bool,
    ) -> Result<Self> {
        if api_base.cannot_be_a_base() || !api_base.path().ends_with('/') {
            bail!("Stripe API base URL must be an absolute directory URL");
        }
        Ok(Self {
            http,
            api_base,
            secret_key: Arc::from(config.secret_key),
            webhook_secret: Arc::from(config.webhook_secret),
            price_id: Arc::from(config.price_id),
            livemode: config.livemode,
            allow_local_checkout_url,
            request_timeout: STRIPE_REQUEST_TIMEOUT,
        })
    }

    async fn retrieve_configured_price(&self) -> Result<StripeConfiguredPrice> {
        self.retrieve_object("prices", self.price_id.as_ref(), "price_")
            .await
    }

    async fn create_checkout_session(
        &self,
        purchase_id: &str,
        quantity_gb: i64,
        success_url: &Url,
        cancel_url: &Url,
    ) -> Result<StripeCheckoutSession> {
        let form = vec![
            ("mode", "payment".to_owned()),
            ("success_url", success_url.as_str().to_owned()),
            ("cancel_url", cancel_url.as_str().to_owned()),
            ("client_reference_id", purchase_id.to_owned()),
            ("metadata[purchase_id]", purchase_id.to_owned()),
            ("metadata[schema_version]", "1".to_owned()),
            (
                "payment_intent_data[metadata][purchase_id]",
                purchase_id.to_owned(),
            ),
            ("line_items[0][price]", self.price_id.to_string()),
            ("line_items[0][quantity]", quantity_gb.to_string()),
        ];
        let url = self.api_base.join("checkout/sessions")?;
        self.send_json(
            self.http
                .post(url)
                .header("Stripe-Version", STRIPE_API_VERSION)
                .header("Idempotency-Key", format!("checkout:{purchase_id}"))
                .bearer_auth(self.secret_key.as_ref())
                .form(&form),
        )
        .await
    }

    async fn retrieve_checkout_session(&self, id: &str) -> Result<StripeCheckoutSession> {
        validate_stripe_id(id, "cs_")?;
        let mut url = self.api_base.join("checkout/sessions/")?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("invalid Stripe API base URL"))?
            .pop_if_empty()
            .push(id);
        url.query_pairs_mut()
            .append_pair("expand[]", "line_items")
            .append_pair("expand[]", "payment_intent.latest_charge");
        self.send_json(
            self.http
                .get(url)
                .header("Stripe-Version", STRIPE_API_VERSION)
                .bearer_auth(self.secret_key.as_ref()),
        )
        .await
    }

    async fn retrieve_refund(&self, id: &str) -> Result<StripeRefund> {
        self.retrieve_object("refunds", id, "re_").await
    }

    async fn retrieve_charge(&self, id: &str) -> Result<StripeCharge> {
        self.retrieve_object("charges", id, "ch_").await
    }

    async fn retrieve_payment_intent(&self, id: &str) -> Result<StripePaymentIntent> {
        self.retrieve_object("payment_intents", id, "pi_").await
    }

    async fn retrieve_dispute(&self, id: &str) -> Result<StripeDispute> {
        self.retrieve_object("disputes", id, "dp_").await
    }

    async fn retrieve_object<T: serde::de::DeserializeOwned>(
        &self,
        collection: &str,
        id: &str,
        prefix: &str,
    ) -> Result<T> {
        validate_stripe_id(id, prefix)?;
        let mut url = self.api_base.join(&format!("{collection}/"))?;
        url.path_segments_mut()
            .map_err(|_| anyhow!("invalid Stripe API base URL"))?
            .pop_if_empty()
            .push(id);
        self.send_json(
            self.http
                .get(url)
                .header("Stripe-Version", STRIPE_API_VERSION)
                .bearer_auth(self.secret_key.as_ref()),
        )
        .await
    }

    async fn send_json<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T> {
        let response = request
            .timeout(self.request_timeout)
            .send()
            .await
            .context("Stripe request failed")?;
        if !response.status().is_success() {
            bail!("Stripe returned HTTP {}", response.status().as_u16());
        }
        response
            .json()
            .await
            .context("Stripe returned an invalid response")
    }

    fn validate_checkout_url(&self, value: &str) -> Result<Url> {
        let url = Url::parse(value).context("Stripe Checkout URL is invalid")?;
        let local = self.allow_local_checkout_url
            && url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost"));
        let stripe = url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| host == "checkout.stripe.com" || host.ends_with(".stripe.com"));
        if !local && !stripe {
            bail!("Stripe Checkout URL has an unexpected origin");
        }
        Ok(url)
    }
}

#[derive(Debug, Deserialize)]
struct StripeCheckoutSession {
    id: String,
    url: Option<String>,
    mode: Option<String>,
    status: Option<String>,
    livemode: bool,
    payment_status: String,
    amount_total: Option<i64>,
    currency: Option<String>,
    client_reference_id: Option<String>,
    metadata: BTreeMap<String, String>,
    payment_intent: Option<Expandable<StripePaymentIntent>>,
    customer: Option<Expandable<StripeReference>>,
    line_items: Option<StripeList<StripeLineItem>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Expandable<T> {
    Id(String),
    Object(T),
}

impl<T> Expandable<T>
where
    T: StripeObject,
{
    fn id(&self) -> &str {
        match self {
            Self::Id(id) => id,
            Self::Object(object) => object.id(),
        }
    }
}

trait StripeObject {
    fn id(&self) -> &str;
}

#[derive(Debug, Deserialize)]
struct StripeReference {
    id: String,
}

impl StripeObject for StripeReference {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct StripePaymentIntent {
    id: String,
    amount_received: i64,
    currency: String,
    latest_charge: Option<Expandable<StripeCharge>>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

impl StripeObject for StripePaymentIntent {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct StripeCharge {
    id: String,
    amount: i64,
    amount_refunded: i64,
    currency: String,
    livemode: bool,
    payment_intent: Option<String>,
}

impl StripeObject for StripeCharge {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
struct StripeRefund {
    id: String,
    amount: i64,
    currency: String,
    status: Option<String>,
    charge: Option<String>,
    payment_intent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StripeDispute {
    id: String,
    amount: i64,
    currency: String,
    charge: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct StripeList<T> {
    data: Vec<T>,
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct StripeLineItem {
    amount_total: i64,
    currency: String,
    quantity: Option<i64>,
    price: Option<StripePrice>,
}

#[derive(Debug, Deserialize)]
struct StripePrice {
    id: String,
}

#[derive(Debug, Deserialize)]
struct StripeConfiguredPrice {
    id: String,
    active: bool,
    livemode: bool,
    currency: String,
    unit_amount: Option<i64>,
    billing_scheme: String,
    #[serde(rename = "type")]
    price_type: String,
    custom_unit_amount: Option<Value>,
    transform_quantity: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct StripeEvent {
    id: String,
    api_version: Option<String>,
    #[serde(rename = "type")]
    event_type: String,
    livemode: bool,
    created: i64,
    data: StripeEventData,
}

#[derive(Debug, Deserialize)]
struct StripeEventData {
    object: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PurchaseState {
    Creating,
    CheckoutOpen,
    Paid,
    Failed,
    Refunded,
    Disputed,
}

impl PurchaseState {
    fn parse(value: &str) -> ApiResult<Self> {
        match value {
            "creating" => Ok(Self::Creating),
            "checkout_open" => Ok(Self::CheckoutOpen),
            "paid" => Ok(Self::Paid),
            "failed" => Ok(Self::Failed),
            "refunded" => Ok(Self::Refunded),
            "disputed" => Ok(Self::Disputed),
            _ => Err(ApiError::internal(anyhow!(
                "invalid billing purchase state"
            ))),
        }
    }
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct BillingPurchase {
    pub id: String,
    pub state: PurchaseState,
    pub quantity_gb: i64,
    pub credit_bytes: i64,
    pub amount_cents: i64,
    pub currency: String,
    pub amount_refunded_cents: i64,
    pub amount_disputed_cents: i64,
    pub receipt_reference: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub paid_at: Option<i64>,
}

#[derive(FromRow)]
struct PurchaseRow {
    id: String,
    account_id: String,
    state: String,
    currency: String,
    unit_amount_cents: i64,
    quantity_gb: i64,
    credit_bytes: i64,
    expected_amount_cents: i64,
    provider_price_id: String,
    provider_checkout_session_id: Option<String>,
    provider_payment_intent_id: Option<String>,
    provider_charge_id: Option<String>,
    provider_dispute_id: Option<String>,
    provider_customer_id: Option<String>,
    livemode: bool,
    amount_paid_cents: i64,
    amount_refunded_cents: i64,
    amount_disputed_cents: i64,
    created_at: i64,
    updated_at: i64,
    paid_at: Option<i64>,
}

impl PurchaseRow {
    fn public(&self) -> ApiResult<BillingPurchase> {
        Ok(BillingPurchase {
            id: self.id.clone(),
            state: PurchaseState::parse(&self.state)?,
            quantity_gb: self.quantity_gb,
            credit_bytes: self.credit_bytes,
            amount_cents: self.expected_amount_cents,
            currency: self.currency.clone(),
            amount_refunded_cents: self.amount_refunded_cents,
            amount_disputed_cents: self.amount_disputed_cents,
            receipt_reference: self.provider_payment_intent_id.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            paid_at: self.paid_at,
        })
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateCheckoutSessionRequest {
    pub quantity_gb: i64,
    pub idempotency_key: String,
}

#[derive(Serialize, ToSchema)]
pub struct CreateCheckoutSessionResponse {
    pub purchase: BillingPurchase,
    pub checkout_url: String,
}

#[derive(Serialize, ToSchema)]
pub struct BillingPurchasesResponse {
    pub purchases: Vec<BillingPurchase>,
}

pub fn router() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(create_checkout_session))
        .routes(routes!(list_purchases))
        .routes(routes!(get_purchase))
        .routes(routes!(stripe_webhook))
}

const PURCHASE_COLUMNS: &str = "id, account_id, state, currency, unit_amount_cents,
     quantity_gb, credit_bytes, expected_amount_cents, provider_price_id,
     provider_checkout_session_id, provider_payment_intent_id, provider_charge_id,
     provider_dispute_id, provider_customer_id, livemode, amount_paid_cents,
     amount_refunded_cents, amount_disputed_cents, created_at, updated_at, paid_at";

#[utoipa::path(
    post,
    path = "/api/me/billing/checkout-sessions",
    summary = "Create a Stripe-hosted credit purchase",
    request_body = CreateCheckoutSessionRequest,
    responses(
        (status = 200, body = CreateCheckoutSessionResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 502, body = ErrorResponse),
        (status = 503, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "billing"
)]
async fn create_checkout_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<CreateCheckoutSessionRequest>,
) -> ApiResult<Json<CreateCheckoutSessionResponse>> {
    let stripe = state.billing.stripe()?.clone();
    let user = authenticated_web_user(&state, &jar).await?;
    validate_checkout_request(&request)?;
    let price = stripe
        .retrieve_configured_price()
        .await
        .map_err(stripe_api_error)?;
    validate_configured_price(&stripe, &price).map_err(stripe_invalid_error)?;
    let now = unix_timestamp()?;
    let purchase_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO billing_purchases
             (id, account_id, client_idempotency_key, provider, state, currency,
              unit_amount_cents, quantity_gb, credit_bytes, expected_amount_cents,
              provider_price_id, livemode, created_at, updated_at)
         VALUES ($1, $2, $3, 'stripe', 'creating', 'usd', $4, $5, $6, $7, $8, $9, $10, $10)
         ON CONFLICT (account_id, client_idempotency_key) DO NOTHING",
    )
    .bind(&purchase_id)
    .bind(&user.0)
    .bind(&request.idempotency_key)
    .bind(CENTS_PER_GB)
    .bind(request.quantity_gb)
    .bind(request.quantity_gb.saturating_mul(BYTES_PER_GB))
    .bind(request.quantity_gb.saturating_mul(CENTS_PER_GB))
    .bind(stripe.price_id.as_ref())
    .bind(stripe.livemode)
    .bind(now)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    let mut purchase =
        select_purchase_by_idempotency(&state.database, &user.0, &request.idempotency_key).await?;
    if purchase.quantity_gb != request.quantity_gb
        || purchase.unit_amount_cents != CENTS_PER_GB
        || purchase.credit_bytes != request.quantity_gb.saturating_mul(BYTES_PER_GB)
        || purchase.expected_amount_cents != request.quantity_gb.saturating_mul(CENTS_PER_GB)
        || purchase.provider_price_id != stripe.price_id.as_ref()
        || purchase.livemode != stripe.livemode
    {
        return Err(ApiError::conflict(
            "billing idempotency key was already used for a different purchase",
        ));
    }
    if !matches!(purchase.state.as_str(), "creating" | "checkout_open") {
        return Err(ApiError::conflict(
            "billing idempotency key belongs to a completed purchase",
        ));
    }

    let session = if let Some(session_id) = purchase.provider_checkout_session_id.as_deref() {
        stripe
            .retrieve_checkout_session(session_id)
            .await
            .map_err(stripe_api_error)?
    } else {
        let (success_url, cancel_url) = checkout_return_urls(&state.billing.app_url, &purchase.id)?;
        stripe
            .create_checkout_session(
                &purchase.id,
                purchase.quantity_gb,
                &success_url,
                &cancel_url,
            )
            .await
            .map_err(stripe_api_error)?
    };
    validate_created_session(&stripe, &purchase, &session)?;
    let checkout_url = session
        .url
        .as_deref()
        .ok_or_else(|| stripe_invalid("Stripe did not return a Checkout URL"))?;
    let checkout_url = stripe
        .validate_checkout_url(checkout_url)
        .map_err(stripe_invalid_error)?;
    purchase =
        bind_checkout_session(&state.database, &purchase.id, &user.0, &session.id, now).await?;
    Ok(Json(CreateCheckoutSessionResponse {
        purchase: purchase.public()?,
        checkout_url: checkout_url.to_string(),
    }))
}

async fn bind_checkout_session(
    database: &super::DatabasePool,
    purchase_id: &str,
    account_id: &str,
    session_id: &str,
    now: i64,
) -> ApiResult<PurchaseRow> {
    let updated = sqlx::query(
        "UPDATE billing_purchases
         SET state = 'checkout_open', provider_checkout_session_id = $1, updated_at = $2
         WHERE id = $3
           AND amount_paid_cents = 0 AND state IN ('creating', 'checkout_open')
           AND (provider_checkout_session_id IS NULL OR provider_checkout_session_id = $1)",
    )
    .bind(session_id)
    .bind(now)
    .bind(purchase_id)
    .execute(database)
    .await
    .map_err(database_error)?;
    let purchase = select_purchase(database, purchase_id, Some(account_id)).await?;
    if updated.rows_affected() != 1
        && !(purchase.provider_checkout_session_id.as_deref() == Some(session_id)
            && purchase.amount_paid_cents > 0
            && matches!(purchase.state.as_str(), "paid" | "refunded" | "disputed"))
    {
        return Err(ApiError::conflict(
            "billing purchase is already bound to another Checkout Session",
        ));
    }
    Ok(purchase)
}

#[utoipa::path(
    get,
    path = "/api/me/billing/purchases",
    summary = "List recent hosted-credit purchases",
    responses(
        (status = 200, body = BillingPurchasesResponse),
        (status = 401, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "billing"
)]
async fn list_purchases(
    State(state): State<AppState>,
    jar: CookieJar,
) -> ApiResult<Json<BillingPurchasesResponse>> {
    let user = authenticated_web_user(&state, &jar).await?;
    let query = format!(
        "SELECT {PURCHASE_COLUMNS} FROM billing_purchases
         WHERE account_id = $1 ORDER BY created_at DESC, id DESC LIMIT 50"
    );
    let purchases = sqlx::query_as::<_, PurchaseRow>(&query)
        .bind(&user.0)
        .fetch_all(&state.database)
        .await
        .map_err(database_error)?
        .iter()
        .map(PurchaseRow::public)
        .collect::<ApiResult<Vec<_>>>()?;
    Ok(Json(BillingPurchasesResponse { purchases }))
}

#[utoipa::path(
    get,
    path = "/api/me/billing/purchases/{purchase_id}",
    summary = "Get one hosted-credit purchase",
    params(("purchase_id" = String, Path)),
    responses(
        (status = 200, body = BillingPurchase),
        (status = 401, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 500, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "billing"
)]
async fn get_purchase(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(purchase_id): Path<String>,
) -> ApiResult<Json<BillingPurchase>> {
    validate_internal_id(&purchase_id, "invalid purchase identifier")?;
    let user = authenticated_web_user(&state, &jar).await?;
    let purchase = select_purchase(&state.database, &purchase_id, Some(&user.0)).await?;
    Ok(Json(purchase.public()?))
}

fn validate_checkout_request(request: &CreateCheckoutSessionRequest) -> ApiResult<()> {
    if !(1..=MAX_QUANTITY_GB).contains(&request.quantity_gb) {
        return Err(ApiError::bad_request(
            "quantity_gb must be between 1 and 20",
        ));
    }
    validate_idempotency_key(&request.idempotency_key)
}

fn validate_configured_price(stripe: &StripeClient, price: &StripeConfiguredPrice) -> Result<()> {
    validate_stripe_id(&price.id, "price_")?;
    if price.id != stripe.price_id.as_ref()
        || !price.active
        || price.livemode != stripe.livemode
        || price.currency != "usd"
        || price.unit_amount != Some(CENTS_PER_GB)
        || price.billing_scheme != "per_unit"
        || price.price_type != "one_time"
        || price.custom_unit_amount.is_some()
        || price.transform_quantity.is_some()
    {
        bail!(
            "configured Stripe Price must be an active, matching-environment, one-time USD Price at {CENTS_PER_GB} cents per GB"
        );
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::bad_request("invalid billing idempotency key"));
    }
    Ok(())
}

fn checkout_return_urls(app_url: &Url, purchase_id: &str) -> ApiResult<(Url, Url)> {
    let build = |outcome: &str| -> ApiResult<Url> {
        let mut url = app_url
            .join("/")
            .map_err(|error| ApiError::internal(error.into()))?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("checkout", outcome)
            .append_pair("purchase_id", purchase_id)
            .finish();
        url.set_fragment(Some(&format!("/dashboard/credits?{query}")));
        Ok(url)
    };
    let success = build("success")?;
    let cancel = build("cancelled")?;
    Ok((success, cancel))
}

fn validate_created_session(
    stripe: &StripeClient,
    purchase: &PurchaseRow,
    session: &StripeCheckoutSession,
) -> ApiResult<()> {
    validate_stripe_id(&session.id, "cs_").map_err(stripe_invalid_error)?;
    if session.livemode != stripe.livemode
        || session.mode.as_deref() != Some("payment")
        || session.status.as_deref() != Some("open")
        || session.payment_status != "unpaid"
        || session.amount_total != Some(purchase.expected_amount_cents)
        || session.currency.as_deref() != Some(purchase.currency.as_str())
        || session.client_reference_id.as_deref() != Some(&purchase.id)
        || session.metadata.get("purchase_id").map(String::as_str) != Some(&purchase.id)
        || session.metadata.get("schema_version").map(String::as_str) != Some("1")
    {
        return Err(stripe_invalid(
            "Stripe Checkout Session did not match the local purchase",
        ));
    }
    Ok(())
}

async fn select_purchase_by_idempotency(
    database: &super::DatabasePool,
    account_id: &str,
    idempotency_key: &str,
) -> ApiResult<PurchaseRow> {
    let query = format!(
        "SELECT {PURCHASE_COLUMNS} FROM billing_purchases
         WHERE account_id = $1 AND client_idempotency_key = $2"
    );
    sqlx::query_as::<_, PurchaseRow>(&query)
        .bind(account_id)
        .bind(idempotency_key)
        .fetch_optional(database)
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::internal(anyhow!("billing purchase insert was not durable")))
}

async fn select_purchase(
    database: &super::DatabasePool,
    purchase_id: &str,
    account_id: Option<&str>,
) -> ApiResult<PurchaseRow> {
    let query = format!(
        "SELECT {PURCHASE_COLUMNS} FROM billing_purchases
         WHERE id = $1 AND ($2::TEXT IS NULL OR account_id = $2)"
    );
    sqlx::query_as::<_, PurchaseRow>(&query)
        .bind(purchase_id)
        .bind(account_id)
        .fetch_optional(database)
        .await
        .map_err(database_error)?
        .ok_or_else(|| ApiError::not_found("billing purchase not found"))
}

#[utoipa::path(
    post,
    path = "/api/billing/stripe/webhook",
    summary = "Receive signed Stripe billing events",
    request_body(content = String, content_type = "application/json"),
    responses(
        (status = 200, description = "Event processed or safely ignored"),
        (status = 400, body = ErrorResponse),
        (status = 502, body = ErrorResponse),
        (status = 503, body = ErrorResponse)
    ),
    tag = "billing"
)]
async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let stripe = state.billing.stripe()?.clone();
    if body.len() > MAX_WEBHOOK_BYTES {
        return Err(ApiError::bad_request("Stripe webhook body is too large"));
    }
    let now = unix_timestamp()?;
    let signature = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::bad_request("Stripe webhook signature is missing"))?;
    verify_webhook_signature(stripe.webhook_secret.as_bytes(), signature, &body, now)?;
    let event: StripeEvent = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("Stripe webhook body is invalid"))?;
    validate_event_envelope(&event)?;
    let object_id = event_object_id(&event.data.object);
    register_event(&state.database, &event, object_id.as_deref(), now).await?;
    if event.livemode != stripe.livemode {
        finish_event(
            &state.database,
            &event.id,
            "rejected",
            Some("wrong_environment"),
            now,
        )
        .await?;
        return Err(ApiError::bad_request(
            "Stripe webhook environment does not match billing configuration",
        ));
    }
    if event_already_finished(&state.database, &event.id).await? {
        return Ok(StatusCode::OK);
    }

    match event.event_type.as_str() {
        "checkout.session.completed" | "checkout.session.async_payment_succeeded" => {
            let Some(session_id) = object_id else {
                reject_event(&state.database, &event.id, "missing_object_id", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe Checkout event has no object identifier",
                ));
            };
            let session = stripe
                .retrieve_checkout_session(&session_id)
                .await
                .map_err(stripe_api_error)?;
            if session.id != session_id {
                reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe Checkout response identifier did not match the event",
                ));
            }
            process_checkout_event(&state, &stripe, &event, session, now).await?;
        }
        "checkout.session.async_payment_failed" | "checkout.session.expired" => {
            let Some(session_id) = object_id else {
                reject_event(&state.database, &event.id, "missing_object_id", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe Checkout event has no object identifier",
                ));
            };
            let session = stripe
                .retrieve_checkout_session(&session_id)
                .await
                .map_err(stripe_api_error)?;
            if session.id != session_id {
                reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe Checkout response identifier did not match the event",
                ));
            }
            process_checkout_failure_event(&state, &event, session, now).await?;
        }
        "refund.created" | "refund.updated" | "refund.failed" => {
            let Some(refund_id) = object_id else {
                reject_event(&state.database, &event.id, "missing_object_id", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe refund event has no object identifier",
                ));
            };
            let refund = stripe
                .retrieve_refund(&refund_id)
                .await
                .map_err(stripe_api_error)?;
            if refund.id != refund_id {
                reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe refund response identifier did not match the event",
                ));
            }
            if refund.status.as_deref() != Some("succeeded") {
                finish_event(&state.database, &event.id, "ignored", None, now).await?;
            } else {
                let charge_id = refund.charge.as_deref().ok_or_else(|| {
                    ApiError::bad_request("Stripe refund has no charge identifier")
                })?;
                let charge = stripe
                    .retrieve_charge(charge_id)
                    .await
                    .map_err(stripe_api_error)?;
                if charge.id != charge_id {
                    reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                    return Err(ApiError::bad_request(
                        "Stripe charge response identifier did not match the refund",
                    ));
                }
                let payment_intent_id = charge.payment_intent.as_deref().ok_or_else(|| {
                    ApiError::bad_request("Stripe charge has no PaymentIntent identifier")
                })?;
                let payment_intent = stripe
                    .retrieve_payment_intent(payment_intent_id)
                    .await
                    .map_err(stripe_api_error)?;
                if payment_intent.id != payment_intent_id {
                    reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                    return Err(ApiError::bad_request(
                        "Stripe PaymentIntent response did not match the charge",
                    ));
                }
                process_refund_event(&state, &event, &refund, &charge, &payment_intent, now)
                    .await?;
            }
        }
        "charge.dispute.funds_withdrawn"
        | "charge.dispute.funds_reinstated"
        | "charge.dispute.closed" => {
            let Some(dispute_id) = object_id else {
                reject_event(&state.database, &event.id, "missing_object_id", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe dispute event has no object identifier",
                ));
            };
            let dispute = stripe
                .retrieve_dispute(&dispute_id)
                .await
                .map_err(stripe_api_error)?;
            if dispute.id != dispute_id {
                reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe dispute response identifier did not match the event",
                ));
            }
            let charge = stripe
                .retrieve_charge(&dispute.charge)
                .await
                .map_err(stripe_api_error)?;
            if charge.id != dispute.charge {
                reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe charge response identifier did not match the dispute",
                ));
            }
            let payment_intent_id = charge.payment_intent.as_deref().ok_or_else(|| {
                ApiError::bad_request("Stripe charge has no PaymentIntent identifier")
            })?;
            let payment_intent = stripe
                .retrieve_payment_intent(payment_intent_id)
                .await
                .map_err(stripe_api_error)?;
            if payment_intent.id != payment_intent_id {
                reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe PaymentIntent response did not match the charge",
                ));
            }
            process_dispute_event(&state, &event, &dispute, &charge, &payment_intent, now).await?;
        }
        _ => {
            finish_event(&state.database, &event.id, "ignored", None, now).await?;
        }
    }
    Ok(StatusCode::OK)
}

fn verify_webhook_signature(secret: &[u8], header: &str, body: &[u8], now: i64) -> ApiResult<()> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for part in header.split(',') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        match name {
            "t" => timestamp = value.parse::<i64>().ok(),
            "v1" => {
                if let Ok(signature) = hex::decode(value) {
                    signatures.push(signature);
                }
            }
            _ => {}
        }
    }
    let timestamp =
        timestamp.ok_or_else(|| ApiError::bad_request("Stripe webhook signature is invalid"))?;
    if now.abs_diff(timestamp) > WEBHOOK_TOLERANCE_SECS as u64 {
        return Err(ApiError::bad_request(
            "Stripe webhook signature timestamp is stale",
        ));
    }
    let signed = format!("{timestamp}.");
    let verified = signatures.iter().any(|signature| {
        HmacSha256::new_from_slice(secret)
            .map(|mut mac| {
                mac.update(signed.as_bytes());
                mac.update(body);
                mac.verify_slice(signature).is_ok()
            })
            .unwrap_or(false)
    });
    if !verified {
        return Err(ApiError::bad_request("Stripe webhook signature is invalid"));
    }
    Ok(())
}

fn validate_event_envelope(event: &StripeEvent) -> ApiResult<()> {
    validate_stripe_id(&event.id, "evt_")
        .map_err(|_| ApiError::bad_request("Stripe webhook event identifier is invalid"))?;
    if event.api_version.as_deref() != Some(STRIPE_API_VERSION)
        || event.event_type.is_empty()
        || event.event_type.len() > 120
        || event.created < 0
    {
        return Err(ApiError::bad_request(
            "Stripe webhook event envelope is invalid",
        ));
    }
    Ok(())
}

fn event_object_id(object: &Value) -> Option<String> {
    object
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 255)
        .map(str::to_owned)
}

async fn register_event(
    database: &super::DatabasePool,
    event: &StripeEvent,
    object_id: Option<&str>,
    received_at: i64,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO billing_provider_events
             (id, provider, event_type, object_id, livemode, provider_created_at, received_at)
         VALUES ($1, 'stripe', $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&event.id)
    .bind(&event.event_type)
    .bind(object_id)
    .bind(event.livemode)
    .bind(event.created)
    .bind(received_at)
    .execute(database)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn event_already_finished(database: &super::DatabasePool, event_id: &str) -> ApiResult<bool> {
    sqlx::query_scalar::<_, Option<i64>>(
        "SELECT processed_at FROM billing_provider_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_one(database)
    .await
    .map_err(database_error)
    .map(|processed_at| processed_at.is_some())
}

async fn finish_event(
    database: &super::DatabasePool,
    event_id: &str,
    outcome: &str,
    error_code: Option<&str>,
    processed_at: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE billing_provider_events
         SET processed_at = COALESCE(processed_at, $2),
             outcome = COALESCE(outcome, $3), error_code = COALESCE(error_code, $4)
         WHERE id = $1",
    )
    .bind(event_id)
    .bind(processed_at)
    .bind(outcome)
    .bind(error_code)
    .execute(database)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn reject_event(
    database: &super::DatabasePool,
    event_id: &str,
    error_code: &str,
    processed_at: i64,
) -> ApiResult<()> {
    finish_event(
        database,
        event_id,
        "rejected",
        Some(error_code),
        processed_at,
    )
    .await
}

async fn process_checkout_failure_event(
    state: &AppState,
    event: &StripeEvent,
    session: StripeCheckoutSession,
    now: i64,
) -> ApiResult<()> {
    let Some(purchase_id) = session.metadata.get("purchase_id") else {
        finish_event(&state.database, &event.id, "ignored", None, now).await?;
        return Ok(());
    };
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    if !lock_pending_event(&mut transaction, &event.id).await? {
        transaction.commit().await.map_err(database_error)?;
        return Ok(());
    }
    let Some(purchase) = select_purchase_for_update(&mut transaction, purchase_id, None).await?
    else {
        finish_event_transaction(&mut transaction, &event.id, "ignored", None, now).await?;
        transaction.commit().await.map_err(database_error)?;
        return Ok(());
    };
    if session.livemode != purchase.livemode
        || session.mode.as_deref() != Some("payment")
        || session.client_reference_id.as_deref() != Some(&purchase.id)
        || session.metadata.get("schema_version").map(String::as_str) != Some("1")
        || purchase
            .provider_checkout_session_id
            .as_deref()
            .is_some_and(|session_id| session_id != session.id)
    {
        finish_event_transaction(
            &mut transaction,
            &event.id,
            "rejected",
            Some("checkout_mismatch"),
            now,
        )
        .await?;
        transaction.commit().await.map_err(database_error)?;
        return Err(ApiError::bad_request(
            "Stripe Checkout Session did not match the local purchase",
        ));
    }
    if purchase.amount_paid_cents == 0 {
        sqlx::query(
            "UPDATE billing_purchases
             SET state = 'failed', provider_checkout_session_id = $1, updated_at = $2
             WHERE id = $3",
        )
        .bind(&session.id)
        .bind(now)
        .bind(&purchase.id)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    }
    finish_event_transaction(&mut transaction, &event.id, "processed", None, now).await?;
    transaction.commit().await.map_err(database_error)?;
    Ok(())
}

struct CheckoutPayment {
    payment_intent_id: String,
    charge_id: String,
    customer_id: Option<String>,
}

async fn process_checkout_event(
    state: &AppState,
    stripe: &StripeClient,
    event: &StripeEvent,
    session: StripeCheckoutSession,
    now: i64,
) -> ApiResult<()> {
    if session.payment_status != "paid" {
        finish_event(&state.database, &event.id, "ignored", None, now).await?;
        return Ok(());
    }
    let Some(purchase_id) = session.metadata.get("purchase_id") else {
        finish_event(&state.database, &event.id, "ignored", None, now).await?;
        return Ok(());
    };
    if validate_internal_id(purchase_id, "invalid Stripe purchase binding").is_err() {
        reject_event(&state.database, &event.id, "invalid_purchase_binding", now).await?;
        return Err(ApiError::bad_request(
            "Stripe Checkout purchase binding is invalid",
        ));
    }
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    if !lock_pending_event(&mut transaction, &event.id).await? {
        transaction.commit().await.map_err(database_error)?;
        return Ok(());
    }
    let Some(mut purchase) =
        select_purchase_for_update(&mut transaction, purchase_id, None).await?
    else {
        finish_event_transaction(&mut transaction, &event.id, "ignored", None, now).await?;
        transaction.commit().await.map_err(database_error)?;
        return Ok(());
    };
    let payment = match validate_paid_session(stripe, &purchase, &session) {
        Ok(payment) => payment,
        Err(error) => {
            finish_event_transaction(
                &mut transaction,
                &event.id,
                "rejected",
                Some("checkout_mismatch"),
                now,
            )
            .await?;
            transaction.commit().await.map_err(database_error)?;
            tracing::warn!(%error, event_id = %event.id, "rejected mismatched Stripe Checkout event");
            return Err(ApiError::bad_request(
                "Stripe Checkout Session did not match the local purchase",
            ));
        }
    };
    if purchase.amount_paid_cents == 0 {
        grant_external_purchase(
            &mut transaction,
            &purchase.account_id,
            &payment.payment_intent_id,
            purchase.credit_bytes,
            event.created,
        )
        .await?;
        sqlx::query(
            "UPDATE billing_purchases
             SET state = 'paid', provider_checkout_session_id = $1,
                 provider_payment_intent_id = $2, provider_charge_id = $3,
                 provider_customer_id = $4, amount_paid_cents = expected_amount_cents,
                 paid_at = $5, updated_at = $6
             WHERE id = $7",
        )
        .bind(&session.id)
        .bind(&payment.payment_intent_id)
        .bind(&payment.charge_id)
        .bind(payment.customer_id.as_deref())
        .bind(event.created)
        .bind(now)
        .bind(&purchase.id)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        purchase.amount_paid_cents = purchase.expected_amount_cents;
    } else if purchase.provider_checkout_session_id.as_deref() != Some(&session.id)
        || purchase.provider_payment_intent_id.as_deref() != Some(&payment.payment_intent_id)
        || purchase.provider_charge_id.as_deref() != Some(&payment.charge_id)
        || purchase
            .provider_customer_id
            .as_deref()
            .is_some_and(|customer_id| payment.customer_id.as_deref() != Some(customer_id))
    {
        finish_event_transaction(
            &mut transaction,
            &event.id,
            "rejected",
            Some("payment_reference_mismatch"),
            now,
        )
        .await?;
        transaction.commit().await.map_err(database_error)?;
        return Err(ApiError::bad_request(
            "Stripe payment references did not match the fulfilled purchase",
        ));
    }
    recompute_account_billing_state(&mut transaction, &purchase.account_id, now).await?;
    finish_event_transaction(&mut transaction, &event.id, "processed", None, now).await?;
    transaction.commit().await.map_err(database_error)?;
    Ok(())
}

fn validate_paid_session(
    stripe: &StripeClient,
    purchase: &PurchaseRow,
    session: &StripeCheckoutSession,
) -> Result<CheckoutPayment> {
    validate_stripe_id(&session.id, "cs_")?;
    if session.livemode != stripe.livemode
        || session.mode.as_deref() != Some("payment")
        || session.status.as_deref() != Some("complete")
        || session.payment_status != "paid"
        || session.amount_total != Some(purchase.expected_amount_cents)
        || session.currency.as_deref() != Some(purchase.currency.as_str())
        || session.client_reference_id.as_deref() != Some(&purchase.id)
        || session.metadata.get("purchase_id").map(String::as_str) != Some(&purchase.id)
        || session.metadata.get("schema_version").map(String::as_str) != Some("1")
    {
        bail!("Checkout Session fields differ from the local purchase");
    }
    let line_items = session
        .line_items
        .as_ref()
        .context("Checkout Session line items were not expanded")?;
    if line_items.has_more || line_items.data.len() != 1 {
        bail!("Checkout Session must contain exactly one line item");
    }
    let item = &line_items.data[0];
    if item.amount_total != purchase.expected_amount_cents
        || item.currency != purchase.currency
        || item.quantity != Some(purchase.quantity_gb)
        || item.price.as_ref().map(|price| price.id.as_str())
            != Some(purchase.provider_price_id.as_str())
    {
        bail!("Checkout Session line item differs from the local purchase");
    }
    let payment_intent = match session.payment_intent.as_ref() {
        Some(Expandable::Object(payment_intent)) => payment_intent,
        _ => bail!("Checkout Session PaymentIntent was not expanded"),
    };
    validate_stripe_id(&payment_intent.id, "pi_")?;
    if payment_intent.amount_received != purchase.expected_amount_cents
        || payment_intent.currency != purchase.currency
        || payment_intent
            .metadata
            .get("purchase_id")
            .map(String::as_str)
            != Some(purchase.id.as_str())
    {
        bail!("PaymentIntent differs from the local purchase");
    }
    let charge_id = payment_intent
        .latest_charge
        .as_ref()
        .context("PaymentIntent has no latest charge")?
        .id()
        .to_owned();
    validate_stripe_id(&charge_id, "ch_")?;
    let customer_id = session
        .customer
        .as_ref()
        .map(Expandable::id)
        .map(str::to_owned);
    if let Some(customer_id) = customer_id.as_deref() {
        validate_stripe_id(customer_id, "cus_")?;
    }
    Ok(CheckoutPayment {
        payment_intent_id: payment_intent.id.clone(),
        charge_id,
        customer_id,
    })
}

async fn process_refund_event(
    state: &AppState,
    event: &StripeEvent,
    refund: &StripeRefund,
    charge: &StripeCharge,
    payment_intent: &StripePaymentIntent,
    now: i64,
) -> ApiResult<()> {
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    if !lock_pending_event(&mut transaction, &event.id).await? {
        transaction.commit().await.map_err(database_error)?;
        return Ok(());
    }
    let purchase = match select_purchase_by_charge_for_update(&mut transaction, &charge.id).await? {
        Some(purchase) => purchase,
        None => {
            if local_purchase_dependency_pending(&mut transaction, payment_intent).await? {
                return Err(billing_dependency_pending());
            }
            finish_event_transaction(&mut transaction, &event.id, "ignored", None, now).await?;
            transaction.commit().await.map_err(database_error)?;
            return Ok(());
        }
    };
    let valid = charge.livemode == event.livemode
        && charge.currency == purchase.currency
        && charge.amount == purchase.amount_paid_cents
        && charge.payment_intent.as_deref() == purchase.provider_payment_intent_id.as_deref()
        && payment_intent.id
            == purchase
                .provider_payment_intent_id
                .as_deref()
                .unwrap_or_default()
        && payment_intent
            .metadata
            .get("purchase_id")
            .map(String::as_str)
            == Some(purchase.id.as_str())
        && refund.currency == purchase.currency
        && refund.amount > 0
        && refund.amount <= purchase.amount_paid_cents
        && refund
            .payment_intent
            .as_deref()
            .is_none_or(|payment_intent| {
                Some(payment_intent) == purchase.provider_payment_intent_id.as_deref()
            })
        && charge.amount_refunded >= purchase.amount_refunded_cents
        && charge.amount_refunded + purchase.amount_disputed_cents <= purchase.amount_paid_cents;
    if !valid {
        finish_event_transaction(
            &mut transaction,
            &event.id,
            "rejected",
            Some("refund_mismatch"),
            now,
        )
        .await?;
        transaction.commit().await.map_err(database_error)?;
        return Err(ApiError::bad_request(
            "Stripe refund did not match the fulfilled purchase",
        ));
    }
    let delta_cents = charge.amount_refunded - purchase.amount_refunded_cents;
    if delta_cents > 0 {
        let amount_bytes = cents_to_bytes(delta_cents)?;
        apply_purchase_adjustment(
            &mut transaction,
            PurchaseAdjustmentSpec {
                account_id: &purchase.account_id,
                purchase_id: &purchase.id,
                amount_bytes: -amount_bytes,
                source_kind: "purchase_refund",
                source_reference: &event.id,
                idempotency_key: &format!("stripe-event:{}", event.id),
                display_label: "Stripe purchase refund",
                created_at: event.created,
            },
        )
        .await?;
    }
    let state_value = purchase_state_after_adjustment(
        purchase.amount_paid_cents,
        charge.amount_refunded,
        purchase.amount_disputed_cents,
    );
    sqlx::query(
        "UPDATE billing_purchases
         SET amount_refunded_cents = $1, state = $2, updated_at = $3 WHERE id = $4",
    )
    .bind(charge.amount_refunded)
    .bind(state_value)
    .bind(now)
    .bind(&purchase.id)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    recompute_account_billing_state(&mut transaction, &purchase.account_id, now).await?;
    finish_event_transaction(&mut transaction, &event.id, "processed", None, now).await?;
    transaction.commit().await.map_err(database_error)?;
    Ok(())
}

async fn process_dispute_event(
    state: &AppState,
    event: &StripeEvent,
    dispute: &StripeDispute,
    charge: &StripeCharge,
    payment_intent: &StripePaymentIntent,
    now: i64,
) -> ApiResult<()> {
    let target_disputed_cents = match (dispute.status.as_str(), event.event_type.as_str()) {
        ("won", _) => 0,
        ("lost", _) => dispute.amount,
        (_, "charge.dispute.funds_withdrawn") => dispute.amount,
        (_, "charge.dispute.funds_reinstated") => 0,
        _ => {
            finish_event(&state.database, &event.id, "ignored", None, now).await?;
            return Ok(());
        }
    };
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    if !lock_pending_event(&mut transaction, &event.id).await? {
        transaction.commit().await.map_err(database_error)?;
        return Ok(());
    }
    let purchase = match select_purchase_by_charge_for_update(&mut transaction, &charge.id).await? {
        Some(purchase) => purchase,
        None => {
            if local_purchase_dependency_pending(&mut transaction, payment_intent).await? {
                return Err(billing_dependency_pending());
            }
            finish_event_transaction(&mut transaction, &event.id, "ignored", None, now).await?;
            transaction.commit().await.map_err(database_error)?;
            return Ok(());
        }
    };
    let valid = charge.livemode == event.livemode
        && charge.currency == purchase.currency
        && charge.amount == purchase.amount_paid_cents
        && charge.payment_intent.as_deref() == purchase.provider_payment_intent_id.as_deref()
        && payment_intent.id
            == purchase
                .provider_payment_intent_id
                .as_deref()
                .unwrap_or_default()
        && payment_intent
            .metadata
            .get("purchase_id")
            .map(String::as_str)
            == Some(purchase.id.as_str())
        && dispute.currency == purchase.currency
        && dispute.amount > 0
        && target_disputed_cents >= 0
        && purchase.amount_refunded_cents + target_disputed_cents <= purchase.amount_paid_cents
        && purchase
            .provider_dispute_id
            .as_deref()
            .is_none_or(|id| id == dispute.id);
    if !valid {
        finish_event_transaction(
            &mut transaction,
            &event.id,
            "rejected",
            Some("dispute_mismatch"),
            now,
        )
        .await?;
        transaction.commit().await.map_err(database_error)?;
        return Err(ApiError::bad_request(
            "Stripe dispute did not match the fulfilled purchase",
        ));
    }
    let delta_cents = target_disputed_cents - purchase.amount_disputed_cents;
    if delta_cents != 0 {
        let amount_bytes = cents_to_bytes(delta_cents.unsigned_abs() as i64)?;
        let (source_kind, label, signed_bytes) = if delta_cents > 0 {
            ("purchase_dispute", "Stripe payment dispute", -amount_bytes)
        } else {
            (
                "dispute_reinstatement",
                "Stripe dispute reinstatement",
                amount_bytes,
            )
        };
        apply_purchase_adjustment(
            &mut transaction,
            PurchaseAdjustmentSpec {
                account_id: &purchase.account_id,
                purchase_id: &purchase.id,
                amount_bytes: signed_bytes,
                source_kind,
                source_reference: &event.id,
                idempotency_key: &format!("stripe-event:{}", event.id),
                display_label: label,
                created_at: event.created,
            },
        )
        .await?;
    }
    let state_value = purchase_state_after_adjustment(
        purchase.amount_paid_cents,
        purchase.amount_refunded_cents,
        target_disputed_cents,
    );
    sqlx::query(
        "UPDATE billing_purchases
         SET provider_dispute_id = COALESCE(provider_dispute_id, $1),
             amount_disputed_cents = $2, state = $3, updated_at = $4
         WHERE id = $5",
    )
    .bind(&dispute.id)
    .bind(target_disputed_cents)
    .bind(state_value)
    .bind(now)
    .bind(&purchase.id)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    recompute_account_billing_state(&mut transaction, &purchase.account_id, now).await?;
    finish_event_transaction(&mut transaction, &event.id, "processed", None, now).await?;
    transaction.commit().await.map_err(database_error)?;
    Ok(())
}

async fn lock_pending_event(
    transaction: &mut Transaction<'_, Postgres>,
    event_id: &str,
) -> ApiResult<bool> {
    let processed_at = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT processed_at FROM billing_provider_events WHERE id = $1 FOR UPDATE",
    )
    .bind(event_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| ApiError::internal(anyhow!("billing event registration was not durable")))?;
    Ok(processed_at.is_none())
}

async fn finish_event_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    event_id: &str,
    outcome: &str,
    error_code: Option<&str>,
    processed_at: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE billing_provider_events
         SET processed_at = $2, outcome = $3, error_code = $4
         WHERE id = $1 AND processed_at IS NULL",
    )
    .bind(event_id)
    .bind(processed_at)
    .bind(outcome)
    .bind(error_code)
    .execute(&mut **transaction)
    .await
    .map_err(database_error)?;
    Ok(())
}

async fn select_purchase_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    purchase_id: &str,
    account_id: Option<&str>,
) -> ApiResult<Option<PurchaseRow>> {
    let query = format!(
        "SELECT {PURCHASE_COLUMNS} FROM billing_purchases
         WHERE id = $1 AND ($2::TEXT IS NULL OR account_id = $2) FOR UPDATE"
    );
    sqlx::query_as::<_, PurchaseRow>(&query)
        .bind(purchase_id)
        .bind(account_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)
}

async fn select_purchase_by_charge_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    charge_id: &str,
) -> ApiResult<Option<PurchaseRow>> {
    let query = format!(
        "SELECT {PURCHASE_COLUMNS} FROM billing_purchases
         WHERE provider_charge_id = $1 FOR UPDATE"
    );
    sqlx::query_as::<_, PurchaseRow>(&query)
        .bind(charge_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(database_error)
}

async fn local_purchase_dependency_pending(
    transaction: &mut Transaction<'_, Postgres>,
    payment_intent: &StripePaymentIntent,
) -> ApiResult<bool> {
    let Some(purchase_id) = payment_intent.metadata.get("purchase_id") else {
        return Ok(false);
    };
    if validate_internal_id(purchase_id, "invalid Stripe purchase binding").is_err() {
        return Ok(false);
    }
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM billing_purchases
             WHERE id = $1 AND amount_paid_cents = 0
         )",
    )
    .bind(purchase_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)
}

async fn recompute_account_billing_state(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: &str,
    updated_at: i64,
) -> ApiResult<()> {
    let (has_paid_purchase, has_dispute) = sqlx::query_as::<_, (bool, bool)>(
        "SELECT EXISTS(
                    SELECT 1 FROM billing_purchases
                    WHERE account_id = $1 AND amount_paid_cents > amount_refunded_cents
                ),
                EXISTS(
                    SELECT 1 FROM billing_purchases
                    WHERE account_id = $1 AND amount_disputed_cents > 0
                )",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    set_account_billing_state(
        transaction,
        account_id,
        if has_paid_purchase {
            ServicePlan::Paid
        } else {
            ServicePlan::Free
        },
        if has_dispute {
            BillingStatus::Review
        } else {
            BillingStatus::Active
        },
        updated_at,
    )
    .await
}

fn purchase_state_after_adjustment(
    paid_cents: i64,
    refunded_cents: i64,
    disputed_cents: i64,
) -> &'static str {
    if disputed_cents > 0 {
        "disputed"
    } else if paid_cents > 0 && refunded_cents == paid_cents {
        "refunded"
    } else {
        "paid"
    }
}

fn cents_to_bytes(cents: i64) -> ApiResult<i64> {
    cents
        .checked_mul(BYTES_PER_CENT)
        .ok_or_else(|| ApiError::internal(anyhow!("billing credit adjustment overflow")))
}

fn validate_internal_id(value: &str, message: &'static str) -> ApiResult<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::bad_request(message));
    }
    Ok(())
}

fn validate_stripe_id(value: &str, prefix: &str) -> Result<()> {
    if !value.starts_with(prefix)
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("invalid Stripe object identifier");
    }
    Ok(())
}

fn stripe_api_error(error: anyhow::Error) -> ApiError {
    tracing::warn!(%error, "Stripe API request failed");
    ApiError::coded(
        StatusCode::BAD_GATEWAY,
        "billing_provider_unavailable",
        "The payment provider is temporarily unavailable",
    )
}

fn billing_dependency_pending() -> ApiError {
    ApiError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "billing_event_dependency_pending",
        "A prerequisite Stripe event has not been processed yet",
    )
}

fn stripe_invalid(message: &'static str) -> ApiError {
    ApiError::coded(StatusCode::BAD_GATEWAY, "billing_provider_invalid", message)
}

fn stripe_invalid_error(error: anyhow::Error) -> ApiError {
    tracing::warn!(%error, "Stripe returned an invalid billing response");
    stripe_invalid("The payment provider returned an invalid response")
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{
        Form, Router,
        extract::{Path as AxumPath, State as AxumState},
        routing::{get, post},
    };
    use axum_extra::extract::cookie::Cookie;

    use super::*;

    #[test]
    fn checkout_returns_to_the_credit_dashboard_hash_route() {
        let app_url = Url::parse("https://llm-notary.example/base").unwrap();
        let (success, cancel) = checkout_return_urls(&app_url, "purchase-id").unwrap();
        assert_eq!(
            success.as_str(),
            "https://llm-notary.example/#/dashboard/credits?checkout=success&purchase_id=purchase-id"
        );
        assert_eq!(
            cancel.as_str(),
            "https://llm-notary.example/#/dashboard/credits?checkout=cancelled&purchase_id=purchase-id"
        );
    }

    #[test]
    fn configured_price_must_match_the_fixed_credit_offer() {
        let billing = BillingService::for_test(
            Url::parse("http://127.0.0.1:1/v1/").unwrap(),
            Url::parse("https://example.test").unwrap(),
        );
        let stripe = billing.stripe().unwrap();
        let mut price = StripeConfiguredPrice {
            id: "price_fixture".to_owned(),
            active: true,
            livemode: false,
            currency: "usd".to_owned(),
            unit_amount: Some(CENTS_PER_GB),
            billing_scheme: "per_unit".to_owned(),
            price_type: "one_time".to_owned(),
            custom_unit_amount: None,
            transform_quantity: None,
        };
        validate_configured_price(stripe, &price).unwrap();
        price.unit_amount = Some(CENTS_PER_GB + 1);
        assert!(validate_configured_price(stripe, &price).is_err());
    }

    #[tokio::test]
    async fn stripe_requests_have_a_total_deadline() {
        async fn slow_refund(AxumPath(id): AxumPath<String>) -> Json<Value> {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Json(serde_json::json!({
                "id": id, "amount": 100, "currency": "usd", "status": "succeeded",
                "charge": "ch_fixture", "payment_intent": "pi_fixture"
            }))
        }

        let app = Router::new().route("/v1/refunds/{id}", get(slow_refund));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut stripe = StripeClient::new(
            reqwest::Client::new(),
            Url::parse(&format!("http://{address}/v1/")).unwrap(),
            StripeConfig {
                secret_key: "sk_test_fixture".to_owned(),
                webhook_secret: "whsec_fixture_secret".to_owned(),
                price_id: "price_fixture".to_owned(),
                livemode: false,
            },
            true,
        )
        .unwrap();
        stripe.request_timeout = Duration::from_millis(25);
        let error = stripe
            .retrieve_refund("re_slow")
            .await
            .expect_err("slow Stripe request must time out");
        assert!(format!("{error:#}").contains("timed out"));
    }
    use crate::{
        AdmissionConfig, SESSION_COOKIE, fresh_database, insert_test_github_user, sha256_hex,
        tests::directory_key,
    };

    #[derive(Default)]
    struct MockStripeState {
        purchase_id: Option<String>,
        paid: bool,
        payment_intent_metadata_valid: bool,
        amount_refunded: i64,
        dispute_status: String,
    }

    fn signed_header(secret: &[u8], timestamp: i64, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(format!("{timestamp}.").as_bytes());
        mac.update(body);
        format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        )
    }

    #[test]
    fn webhook_signature_covers_the_exact_body_and_has_a_bounded_timestamp() {
        let body = br#"{"id":"evt_fixture"}"#;
        let header = signed_header(b"whsec_fixture_secret", 10_000, body);
        verify_webhook_signature(b"whsec_fixture_secret", &header, body, 10_100).unwrap();
        assert!(
            verify_webhook_signature(
                b"whsec_fixture_secret",
                &header,
                br#"{"id":"evt_changed"}"#,
                10_100
            )
            .is_err()
        );
        assert!(verify_webhook_signature(b"whsec_fixture_secret", &header, body, 10_301).is_err());
    }

    async fn mock_checkout(
        AxumState(state): AxumState<Arc<Mutex<MockStripeState>>>,
        Form(form): Form<BTreeMap<String, String>>,
    ) -> Json<Value> {
        let purchase_id = form.get("client_reference_id").unwrap().clone();
        state.lock().unwrap().purchase_id = Some(purchase_id.clone());
        Json(checkout_json(&state, &purchase_id, false))
    }

    async fn mock_price(AxumPath(id): AxumPath<String>) -> Json<Value> {
        Json(serde_json::json!({
            "id": id,
            "active": true,
            "livemode": false,
            "currency": "usd",
            "unit_amount": CENTS_PER_GB,
            "billing_scheme": "per_unit",
            "type": "one_time",
            "custom_unit_amount": null,
            "transform_quantity": null
        }))
    }

    async fn mock_retrieve_checkout(
        AxumPath(_session_id): AxumPath<String>,
        AxumState(state): AxumState<Arc<Mutex<MockStripeState>>>,
    ) -> Json<Value> {
        let purchase_id = state.lock().unwrap().purchase_id.clone().unwrap();
        let paid = state.lock().unwrap().paid;
        Json(checkout_json(&state, &purchase_id, paid))
    }

    fn checkout_json(state: &Arc<Mutex<MockStripeState>>, purchase_id: &str, paid: bool) -> Value {
        let payment_intent_purchase_id = if state.lock().unwrap().payment_intent_metadata_valid {
            purchase_id
        } else {
            "wrong-purchase"
        };
        serde_json::json!({
            "id": "cs_fixture",
            "url": "http://127.0.0.1/checkout/cs_fixture",
            "mode": "payment",
            "status": if paid { "complete" } else { "open" },
            "livemode": false,
            "payment_status": if paid { "paid" } else { "unpaid" },
            "amount_total": 1000,
            "currency": "usd",
            "client_reference_id": purchase_id,
            "metadata": { "purchase_id": purchase_id, "schema_version": "1" },
            "customer": if paid { serde_json::json!({ "id": "cus_fixture" }) } else { Value::Null },
            "payment_intent": if paid {
                serde_json::json!({
                    "id": "pi_fixture",
                    "amount_received": 1000,
                    "currency": "usd",
                    "metadata": { "purchase_id": payment_intent_purchase_id },
                    "latest_charge": { "id": "ch_fixture", "amount": 1000,
                        "amount_refunded": 0, "currency": "usd", "livemode": false,
                        "payment_intent": "pi_fixture" }
                })
            } else { Value::Null },
            "line_items": if paid {
                serde_json::json!({
                    "has_more": false,
                    "data": [{ "amount_total": 1000, "currency": "usd", "quantity": 2,
                        "price": { "id": "price_fixture" } }]
                })
            } else { Value::Null }
        })
    }

    async fn mock_refund(AxumPath(id): AxumPath<String>) -> Json<Value> {
        Json(serde_json::json!({
            "id": id,
            "amount": 100,
            "currency": "usd",
            "status": "succeeded",
            "charge": "ch_fixture",
            "payment_intent": "pi_fixture"
        }))
    }

    async fn mock_charge(
        AxumPath(id): AxumPath<String>,
        AxumState(state): AxumState<Arc<Mutex<MockStripeState>>>,
    ) -> Json<Value> {
        let state = state.lock().unwrap();
        Json(serde_json::json!({
            "id": id,
            "amount": 1000,
            "amount_refunded": state.amount_refunded,
            "currency": "usd",
            "livemode": false,
            "payment_intent": "pi_fixture"
        }))
    }

    async fn mock_dispute(
        AxumPath(id): AxumPath<String>,
        AxumState(state): AxumState<Arc<Mutex<MockStripeState>>>,
    ) -> Json<Value> {
        let state = state.lock().unwrap();
        Json(serde_json::json!({
            "id": id,
            "amount": 400,
            "currency": "usd",
            "charge": "ch_fixture",
            "status": state.dispute_status
        }))
    }

    async fn mock_payment_intent(
        AxumPath(id): AxumPath<String>,
        AxumState(state): AxumState<Arc<Mutex<MockStripeState>>>,
    ) -> Json<Value> {
        let purchase_id = state.lock().unwrap().purchase_id.clone().unwrap();
        Json(serde_json::json!({
            "id": id,
            "amount_received": 1000,
            "currency": "usd",
            "latest_charge": "ch_fixture",
            "metadata": { "purchase_id": purchase_id }
        }))
    }

    async fn test_state(billing: BillingService) -> AppState {
        let database = fresh_database().await;
        AppState {
            database: database.pool.clone(),
            _test_database: Some(database),
            http: reqwest::Client::new(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "secret".to_owned(),
            github_callback_url: Url::parse("https://example.test/api/auth/github/callback")
                .unwrap(),
            google_client_id: "google-client-id".to_owned(),
            google_client_secret: "google-secret".to_owned(),
            google_callback_url: Url::parse("https://example.test/api/auth/google/callback")
                .unwrap(),
            app_url: Url::parse("https://example.test").unwrap(),
            secure_cookies: true,
            notary_directory: directory_key(),
            publish: crate::publish::PublishService::disabled_for_test(),
            admission: Arc::new(AdmissionConfig::for_test()),
            billing,
        }
    }

    async fn deliver_event(
        state: &AppState,
        event: Value,
        timestamp: i64,
    ) -> ApiResult<StatusCode> {
        let body = serde_json::to_vec(&event).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "stripe-signature",
            signed_header(b"whsec_fixture_secret", timestamp, &body)
                .parse()
                .unwrap(),
        );
        stripe_webhook(State(state.clone()), headers, Bytes::from(body)).await
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL container"]
    async fn checkout_webhooks_are_idempotent_and_reconcile_refunds_and_disputes() {
        let mock = Arc::new(Mutex::new(MockStripeState {
            dispute_status: "needs_response".to_owned(),
            payment_intent_metadata_valid: true,
            ..Default::default()
        }));
        let app = Router::new()
            .route("/v1/prices/{id}", get(mock_price))
            .route("/v1/checkout/sessions", post(mock_checkout))
            .route("/v1/checkout/sessions/{id}", get(mock_retrieve_checkout))
            .route("/v1/refunds/{id}", get(mock_refund))
            .route("/v1/charges/{id}", get(mock_charge))
            .route("/v1/disputes/{id}", get(mock_dispute))
            .route("/v1/payment_intents/{id}", get(mock_payment_intent))
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let billing = BillingService::for_test(
            Url::parse(&format!("http://{address}/v1/")).unwrap(),
            Url::parse("https://example.test").unwrap(),
        );
        let state = test_state(billing).await;
        insert_test_github_user(&state.database, "billing-user", 90, "billing-user").await;
        let now = unix_timestamp().unwrap();
        let session_token = "billing-browser-session";
        sqlx::query(
            "INSERT INTO sessions (token_hash, user_id, expires_at, created_at)
             VALUES ($1, 'billing-user', $2, $3)",
        )
        .bind(sha256_hex(session_token.as_bytes()))
        .bind(now + 600)
        .bind(now)
        .execute(&state.database)
        .await
        .unwrap();
        let jar = CookieJar::new().add(Cookie::new(SESSION_COOKIE, session_token));
        let checkout = create_checkout_session(
            State(state.clone()),
            jar,
            Json(CreateCheckoutSessionRequest {
                quantity_gb: 2,
                idempotency_key: "checkout-fixture-1".to_owned(),
            }),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(checkout.purchase.state, PurchaseState::CheckoutOpen);
        assert!(checkout.checkout_url.contains("/checkout/cs_fixture"));

        mock.lock().unwrap().paid = true;
        state
            .billing
            .stripe()
            .unwrap()
            .retrieve_checkout_session("cs_fixture")
            .await
            .unwrap();
        mock.lock().unwrap().amount_refunded = 100;
        let refund_event = serde_json::json!({
            "id": "evt_refund", "api_version": STRIPE_API_VERSION,
            "type": "refund.created", "livemode": false,
            "created": now + 1, "data": { "object": { "id": "re_fixture" } }
        });
        let dependency = deliver_event(&state, refund_event.clone(), now)
            .await
            .unwrap_err();
        assert_eq!(dependency.code, "billing_event_dependency_pending");
        let completed = serde_json::json!({
            "id": "evt_checkout", "api_version": STRIPE_API_VERSION,
            "type": "checkout.session.completed",
            "livemode": false, "created": now,
            "data": { "object": { "id": "cs_fixture" } }
        });
        mock.lock().unwrap().payment_intent_metadata_valid = false;
        let mismatched = serde_json::json!({
            "id": "evt_checkout_bad_metadata", "api_version": STRIPE_API_VERSION,
            "type": "checkout.session.completed",
            "livemode": false, "created": now,
            "data": { "object": { "id": "cs_fixture" } }
        });
        let mismatch = deliver_event(&state, mismatched, now)
            .await
            .expect_err("mismatched PaymentIntent metadata must be rejected");
        assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);
        let premature_grants: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notary_credit_grants
             WHERE account_id = 'billing-user' AND source_kind = 'external_purchase'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(premature_grants, 0);
        mock.lock().unwrap().payment_intent_metadata_valid = true;
        deliver_event(&state, completed.clone(), now).await.unwrap();
        deliver_event(&state, completed, now).await.unwrap();
        let grants: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(amount_bytes), 0)::BIGINT
             FROM notary_credit_grants WHERE account_id = 'billing-user'
               AND source_kind = 'external_purchase'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(grants, (1, 2 * BYTES_PER_GB));
        let raced_binding = bind_checkout_session(
            &state.database,
            &checkout.purchase.id,
            "billing-user",
            "cs_fixture",
            now + 1,
        )
        .await
        .unwrap();
        assert_eq!(raced_binding.state, "paid");
        assert_eq!(raced_binding.amount_paid_cents, 2 * CENTS_PER_GB);

        deliver_event(&state, refund_event, now).await.unwrap();
        deliver_event(
            &state,
            serde_json::json!({
                "id": "evt_dispute", "api_version": STRIPE_API_VERSION,
                "type": "charge.dispute.funds_withdrawn",
                "livemode": false, "created": now + 2,
                "data": { "object": { "id": "dp_fixture" } }
            }),
            now,
        )
        .await
        .unwrap();
        let profile: (String, String) = sqlx::query_as(
            "SELECT service_plan, billing_status FROM account_billing_profiles
             WHERE account_id = 'billing-user'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(profile, ("paid".to_owned(), "review".to_owned()));

        mock.lock().unwrap().dispute_status = "won".to_owned();
        deliver_event(
            &state,
            serde_json::json!({
                "id": "evt_reinstated", "api_version": STRIPE_API_VERSION,
                "type": "charge.dispute.funds_reinstated",
                "livemode": false, "created": now + 3,
                "data": { "object": { "id": "dp_fixture" } }
            }),
            now,
        )
        .await
        .unwrap();
        // A late withdrawn event retrieves the current won state and cannot
        // reapply the dispute after reinstatement.
        deliver_event(
            &state,
            serde_json::json!({
                "id": "evt_late_withdrawn", "api_version": STRIPE_API_VERSION,
                "type": "charge.dispute.funds_withdrawn",
                "livemode": false, "created": now,
                "data": { "object": { "id": "dp_fixture" } }
            }),
            now,
        )
        .await
        .unwrap();
        let profile: (String, String) = sqlx::query_as(
            "SELECT service_plan, billing_status FROM account_billing_profiles
             WHERE account_id = 'billing-user'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(profile, ("paid".to_owned(), "active".to_owned()));

        mock.lock().unwrap().amount_refunded = 1000;
        deliver_event(
            &state,
            serde_json::json!({
                "id": "evt_full_refund", "api_version": STRIPE_API_VERSION,
                "type": "refund.updated", "livemode": false,
                "created": now + 4, "data": { "object": { "id": "re_full" } }
            }),
            now,
        )
        .await
        .unwrap();
        let purchase =
            select_purchase(&state.database, &checkout.purchase.id, Some("billing-user"))
                .await
                .unwrap();
        assert_eq!(purchase.state, "refunded");
        let profile: (String, String) = sqlx::query_as(
            "SELECT service_plan, billing_status FROM account_billing_profiles
             WHERE account_id = 'billing-user'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(profile, ("free".to_owned(), "active".to_owned()));
        let adjustments: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount_bytes), 0)::BIGINT
             FROM notary_credit_adjustments WHERE account_id = 'billing-user'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(adjustments, -(2 * BYTES_PER_GB));

        let wrong_environment = deliver_event(
            &state,
            serde_json::json!({
                "id": "evt_wrong_environment", "api_version": STRIPE_API_VERSION,
                "type": "checkout.session.completed",
                "livemode": true, "created": now + 5,
                "data": { "object": { "id": "cs_fixture" } }
            }),
            now,
        )
        .await
        .unwrap_err();
        assert_eq!(wrong_environment.status, StatusCode::BAD_REQUEST);
        let event_outcome: String = sqlx::query_scalar(
            "SELECT outcome FROM billing_provider_events WHERE id = 'evt_wrong_environment'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(event_outcome, "rejected");
    }
}
