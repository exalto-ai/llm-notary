mod store;
mod stripe;
mod webhooks;

use anyhow::{Result, anyhow};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use url::Url;
use utoipa::ToSchema;
use utoipa_axum::{router::OpenApiRouter, routes};
use uuid::Uuid;

use self::{store::*, stripe::*};
#[cfg(test)]
use super::StripeConfig;
use super::{
    ApiError, ApiResult, BillingConfig, ErrorResponse, NotaryApiState,
    auth::authenticated_web_user, credits::Plan, database_error, unix_timestamp,
};

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
    public_origin: Url,
}

impl BillingService {
    pub fn from_config(
        config: &BillingConfig,
        public_origin: &Url,
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
            public_origin: public_origin.clone(),
        })
    }

    #[cfg(test)]
    pub(crate) fn disabled_for_test() -> Self {
        Self {
            stripe: None,
            public_origin: Url::parse("https://example.test").unwrap(),
        }
    }

    #[cfg(test)]
    fn for_test(api_base: Url, public_origin: Url) -> Self {
        Self {
            stripe: Some(
                StripeClient::new(
                    reqwest::Client::new(),
                    api_base,
                    StripeConfig {
                        secret_key: "sk_test_fixture".to_owned(),
                        webhook_secret: "whsec_fixture_secret".to_owned(),
                        credit_price_id: "price_fixture".to_owned(),
                        one_gb_price_id: Some("price_one_gb_fixture".to_owned()),
                        ten_gb_price_id: Some("price_ten_gb_fixture".to_owned()),
                        livemode: false,
                    },
                    true,
                )
                .unwrap(),
            ),
            public_origin,
        }
    }

    fn stripe(&self) -> ApiResult<&StripeClient> {
        self.stripe.as_ref().ok_or_else(|| {
            ApiError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                "billing_unavailable",
                "Hosted billing is not configured",
            )
        })
    }

    fn subscription_stripe(&self) -> ApiResult<&StripeClient> {
        let stripe = self.stripe()?;
        if !stripe.subscriptions_configured() {
            return Err(ApiError::coded(
                StatusCode::SERVICE_UNAVAILABLE,
                "billing_unavailable",
                "Hosted subscription billing is not configured",
            ));
        }
        Ok(stripe)
    }

    pub(crate) fn purchase_mode(&self) -> BillingPurchaseMode {
        match self.stripe.as_ref() {
            None => BillingPurchaseMode::Disabled,
            Some(stripe) if stripe.livemode => BillingPurchaseMode::Live,
            Some(_) => BillingPurchaseMode::Test,
        }
    }

    pub(crate) fn subscriptions_configured(&self) -> bool {
        self.stripe
            .as_ref()
            .is_some_and(StripeClient::subscriptions_configured)
    }
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

#[derive(Deserialize, ToSchema)]
pub struct CreateSubscriptionCheckoutRequest {
    pub plan: SubscriptionPlan,
    pub idempotency_key: String,
}

#[derive(Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionPlan {
    OneGb,
    TenGb,
}

impl SubscriptionPlan {
    fn plan(self) -> Plan {
        match self {
            Self::OneGb => Plan::OneGb,
            Self::TenGb => Plan::TenGb,
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct CreateSubscriptionCheckoutResponse {
    pub checkout_url: String,
}

#[derive(Serialize, ToSchema)]
pub struct CreatePortalSessionResponse {
    pub portal_url: String,
}

pub fn router() -> OpenApiRouter<NotaryApiState> {
    OpenApiRouter::new()
        .routes(routes!(create_checkout_session))
        .routes(routes!(create_subscription_checkout_session))
        .routes(routes!(create_portal_session))
        .routes(routes!(list_purchases))
        .routes(routes!(get_purchase))
        .routes(routes!(stripe_webhook))
}

#[utoipa::path(
    post,
    path = "/api/billing/subscription-checkout-sessions",
    summary = "Create a Stripe-hosted subscription Checkout session",
    request_body = CreateSubscriptionCheckoutRequest,
    responses(
        (status = 200, body = CreateSubscriptionCheckoutResponse),
        (status = 400, body = ErrorResponse),
        (status = 401, body = ErrorResponse),
        (status = 409, body = ErrorResponse),
        (status = 502, body = ErrorResponse),
        (status = 503, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "billing"
)]
async fn create_subscription_checkout_session(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Json(request): Json<CreateSubscriptionCheckoutRequest>,
) -> ApiResult<Json<CreateSubscriptionCheckoutResponse>> {
    let stripe = state.billing.subscription_stripe()?.clone();
    let user = authenticated_web_user(&state, &jar).await?;
    validate_idempotency_key(&request.idempotency_key)?;
    let plan = request.plan.plan();
    if super::credits::account_billing_state(&state.database, &user.0)
        .await?
        .plan
        != Plan::Free
    {
        return Err(ApiError::conflict(
            "Use the billing portal to change an existing subscription",
        ));
    }
    let price = stripe
        .retrieve_subscription_price(plan)
        .await
        .map_err(stripe_api_error)?;
    validate_subscription_price(&stripe, plan, &price).map_err(stripe_invalid_error)?;
    let now = unix_timestamp()?;
    let checkout_id = Uuid::new_v4().to_string();
    let price_id = stripe
        .subscription_price_id(plan)
        .map_err(stripe_invalid_error)?;
    type CheckoutRow = (String, String, String, String, bool, Option<String>);
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    sqlx::query("SELECT account_id FROM accounts WHERE account_id = $1 FOR UPDATE")
        .bind(&user.0)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
    let has_subscription: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM billing_subscriptions
             WHERE account_id = $1 AND status NOT IN ('canceled', 'incomplete_expired')
         )",
    )
    .bind(&user.0)
    .fetch_one(&mut *transaction)
    .await
    .map_err(database_error)?;
    if has_subscription {
        return Err(ApiError::conflict(
            "Use the billing portal to change an existing subscription",
        ));
    }
    let mut row = sqlx::query_as::<_, CheckoutRow>(
        "SELECT id, target_plan, state, provider_price_id, livemode,
                provider_checkout_session_id
         FROM billing_subscription_checkouts
         WHERE account_id = $1 AND client_idempotency_key = $2",
    )
    .bind(&user.0)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(database_error)?;
    if row.is_none() {
        row = sqlx::query_as::<_, CheckoutRow>(
            "SELECT id, target_plan, state, provider_price_id, livemode,
                    provider_checkout_session_id
             FROM billing_subscription_checkouts
             WHERE account_id = $1 AND state IN ('creating', 'checkout_open')
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&user.0)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(database_error)?;
    }
    let row = if let Some(row) = row {
        row
    } else {
        sqlx::query(
            "INSERT INTO billing_subscription_checkouts
                 (id, account_id, client_idempotency_key, target_plan, state, provider,
                  provider_price_id, livemode, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'creating', 'stripe', $5, $6, $7, $7)",
        )
        .bind(&checkout_id)
        .bind(&user.0)
        .bind(&request.idempotency_key)
        .bind(plan.as_str())
        .bind(price_id)
        .bind(stripe.livemode)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(database_error)?;
        (
            checkout_id,
            plan.as_str().to_owned(),
            "creating".to_owned(),
            price_id.to_owned(),
            stripe.livemode,
            None,
        )
    };
    transaction.commit().await.map_err(database_error)?;
    if row.1 != plan.as_str() {
        return Err(ApiError::conflict(
            "another subscription Checkout is already open for a different plan",
        ));
    }
    if row.3 != price_id || row.4 != stripe.livemode {
        return Err(ApiError::conflict(
            "the existing subscription Checkout uses different billing configuration",
        ));
    }
    if !matches!(row.2.as_str(), "creating" | "checkout_open") {
        return Err(ApiError::conflict(
            "subscription Checkout is already complete",
        ));
    }
    let session = if let Some(session_id) = row.5.as_deref() {
        stripe
            .retrieve_checkout_session(session_id)
            .await
            .map_err(stripe_api_error)?
    } else {
        let (success_url, cancel_url) = subscription_return_urls(&state.billing.public_origin)?;
        let customer_id = preferred_customer_id(&state.database, &user.0).await?;
        stripe
            .create_subscription_checkout_session(
                &row.0,
                &user.0,
                plan,
                customer_id.as_deref(),
                &success_url,
                &cancel_url,
            )
            .await
            .map_err(stripe_api_error)?
    };
    validate_subscription_session_binding(&stripe, &row.0, &session)?;
    if session.status.as_deref() == Some("expired") {
        sqlx::query(
            "UPDATE billing_subscription_checkouts
             SET state = 'expired', provider_checkout_session_id = COALESCE(
                     provider_checkout_session_id, $1
                 ), updated_at = $2
             WHERE id = $3 AND account_id = $4
               AND state IN ('creating', 'checkout_open')
               AND (provider_checkout_session_id IS NULL OR provider_checkout_session_id = $1)",
        )
        .bind(&session.id)
        .bind(now)
        .bind(&row.0)
        .bind(&user.0)
        .execute(&state.database)
        .await
        .map_err(database_error)?;
        return Err(ApiError::conflict(
            "Subscription Checkout expired; start a new Checkout",
        ));
    }
    validate_created_subscription_session(&stripe, &row.0, &session)?;
    let checkout_url = session
        .url
        .as_deref()
        .ok_or_else(|| stripe_invalid("Stripe did not return a Checkout URL"))?;
    let checkout_url = stripe
        .validate_checkout_url(checkout_url)
        .map_err(stripe_invalid_error)?;
    sqlx::query(
        "UPDATE billing_subscription_checkouts
         SET state = 'checkout_open', provider_checkout_session_id = $1, updated_at = $2
         WHERE id = $3 AND account_id = $4 AND state IN ('creating', 'checkout_open')
           AND (provider_checkout_session_id IS NULL OR provider_checkout_session_id = $1)",
    )
    .bind(&session.id)
    .bind(now)
    .bind(&row.0)
    .bind(&user.0)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    Ok(Json(CreateSubscriptionCheckoutResponse {
        checkout_url: checkout_url.to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/billing/portal-sessions",
    summary = "Create a Stripe Billing Portal session",
    responses(
        (status = 200, body = CreatePortalSessionResponse),
        (status = 401, body = ErrorResponse),
        (status = 404, body = ErrorResponse),
        (status = 502, body = ErrorResponse),
        (status = 503, body = ErrorResponse)
    ),
    security(("browserSession" = [])),
    tag = "billing"
)]
async fn create_portal_session(
    State(state): State<NotaryApiState>,
    jar: CookieJar,
) -> ApiResult<Json<CreatePortalSessionResponse>> {
    let stripe = state.billing.stripe()?.clone();
    let user = authenticated_web_user(&state, &jar).await?;
    let customer_id = active_subscription_customer_id(&state.database, &user.0)
        .await?
        .ok_or_else(|| ApiError::not_found("This account has no active Stripe subscription"))?;
    let mut return_url = state.billing.public_origin.clone();
    return_url.set_fragment(Some("/dashboard/credits"));
    let portal = stripe
        .create_portal_session(&customer_id, &return_url)
        .await
        .map_err(stripe_api_error)?;
    validate_stripe_id(&portal.id, "bps_").map_err(stripe_invalid_error)?;
    if portal.customer.id() != customer_id || portal.livemode != stripe.livemode {
        return Err(stripe_invalid(
            "Stripe Billing Portal Session did not match the account",
        ));
    }
    let portal_url = stripe
        .validate_portal_url(&portal.url)
        .map_err(stripe_invalid_error)?;
    Ok(Json(CreatePortalSessionResponse {
        portal_url: portal_url.to_string(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/billing/checkout-sessions",
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
    State(state): State<NotaryApiState>,
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
    .bind(stripe.credit_price_id.as_ref())
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
        || purchase.provider_price_id != stripe.credit_price_id.as_ref()
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
        let (success_url, cancel_url) =
            checkout_return_urls(&state.billing.public_origin, &purchase.id)?;
        let customer_id = preferred_customer_id(&state.database, &user.0).await?;
        stripe
            .create_checkout_session(
                &purchase.id,
                purchase.quantity_gb,
                customer_id.as_deref(),
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

#[utoipa::path(
    get,
    path = "/api/billing/purchases",
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
    State(state): State<NotaryApiState>,
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
    path = "/api/billing/purchases/{purchase_id}",
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
    State(state): State<NotaryApiState>,
    jar: CookieJar,
    Path(purchase_id): Path<String>,
) -> ApiResult<Json<BillingPurchase>> {
    validate_internal_id(&purchase_id, "invalid purchase identifier")?;
    let user = authenticated_web_user(&state, &jar).await?;
    let purchase = select_purchase(&state.database, &purchase_id, Some(&user.0)).await?;
    Ok(Json(purchase.public()?))
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
    State(state): State<NotaryApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    webhooks::handle_stripe_webhook(State(state), headers, body).await
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use axum::{
        Form, Router,
        extract::{Path as AxumPath, State as AxumState},
        routing::{get, post},
    };
    use axum_extra::extract::cookie::Cookie;
    use hmac::Mac;
    use serde_json::Value;

    use crate::{StripeConfig, credits::BillingStatus};

    use super::webhooks::{HmacSha256, verify_webhook_signature};

    use super::*;

    #[test]
    fn checkout_returns_to_the_credit_dashboard_hash_route() {
        let public_origin = Url::parse("https://llm-notary.example/base").unwrap();
        let (success, cancel) = checkout_return_urls(&public_origin, "purchase-id").unwrap();
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
    fn subscription_checkout_returns_to_the_plan_dashboard_hash_route() {
        let public_origin = Url::parse("https://llm-notary.example/base").unwrap();
        let (success, cancel) = subscription_return_urls(&public_origin).unwrap();
        assert_eq!(
            success.as_str(),
            "https://llm-notary.example/#/dashboard/credits?subscription=success"
        );
        assert_eq!(
            cancel.as_str(),
            "https://llm-notary.example/#/dashboard/credits?subscription=cancelled"
        );
    }

    #[test]
    fn one_time_billing_stays_available_without_subscription_prices() {
        let billing = BillingService::from_config(
            &BillingConfig {
                stripe: Some(StripeConfig {
                    secret_key: "sk_test_fixture".to_owned(),
                    webhook_secret: "whsec_fixture_secret".to_owned(),
                    credit_price_id: "price_fixture".to_owned(),
                    one_gb_price_id: None,
                    ten_gb_price_id: None,
                    livemode: false,
                }),
            },
            &Url::parse("https://example.test").unwrap(),
            reqwest::Client::new(),
        )
        .unwrap();

        assert_eq!(billing.purchase_mode(), BillingPurchaseMode::Test);
        assert!(!billing.subscriptions_configured());
        assert!(billing.stripe().is_ok());
        assert!(billing.subscription_stripe().is_err());
    }

    #[test]
    fn expired_subscription_checkout_keeps_a_valid_local_binding() {
        let billing = BillingService::for_test(
            Url::parse("http://127.0.0.1:1/v1/").unwrap(),
            Url::parse("https://example.test").unwrap(),
        );
        let stripe = billing.stripe().unwrap();
        let session: StripeCheckoutSession = serde_json::from_value(serde_json::json!({
            "id": "cs_expired_fixture",
            "url": null,
            "mode": "subscription",
            "status": "expired",
            "livemode": false,
            "payment_status": "unpaid",
            "amount_total": null,
            "currency": null,
            "client_reference_id": "checkout-fixture",
            "metadata": {
                "billing_kind": "subscription",
                "subscription_checkout_id": "checkout-fixture",
                "schema_version": "2"
            },
            "payment_intent": null,
            "subscription": null,
            "customer": null,
            "line_items": null
        }))
        .unwrap();
        validate_subscription_session_binding(stripe, "checkout-fixture", &session).unwrap();
        assert!(
            validate_created_subscription_session(stripe, "checkout-fixture", &session).is_err()
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
            recurring: None,
        };
        validate_configured_price(stripe, &price).unwrap();
        price.unit_amount = Some(CENTS_PER_GB + 1);
        assert!(validate_configured_price(stripe, &price).is_err());
    }

    #[test]
    fn subscription_prices_must_match_the_two_monthly_plans() {
        let billing = BillingService::for_test(
            Url::parse("http://127.0.0.1:1/v1/").unwrap(),
            Url::parse("https://example.test").unwrap(),
        );
        let stripe = billing.stripe().unwrap();
        let mut price = StripeConfiguredPrice {
            id: "price_one_gb_fixture".to_owned(),
            active: true,
            livemode: false,
            currency: "usd".to_owned(),
            unit_amount: Some(999),
            billing_scheme: "per_unit".to_owned(),
            price_type: "recurring".to_owned(),
            custom_unit_amount: None,
            transform_quantity: None,
            recurring: Some(StripeRecurring {
                interval: "month".to_owned(),
                interval_count: 1,
                usage_type: "licensed".to_owned(),
            }),
        };
        validate_subscription_price(stripe, Plan::OneGb, &price).unwrap();

        price.id = "price_ten_gb_fixture".to_owned();
        price.unit_amount = Some(4_999);
        validate_subscription_price(stripe, Plan::TenGb, &price).unwrap();
        price.recurring.as_mut().unwrap().interval = "year".to_owned();
        assert!(validate_subscription_price(stripe, Plan::TenGb, &price).is_err());
    }

    #[test]
    fn portal_plan_changes_use_the_configured_price_as_authority() {
        let billing = BillingService::for_test(
            Url::parse("http://127.0.0.1:1/v1/").unwrap(),
            Url::parse("https://example.test").unwrap(),
        );
        let stripe = billing.stripe().unwrap();
        let subscription: StripeSubscription = serde_json::from_value(serde_json::json!({
            "id": "sub_fixture",
            "status": "active",
            "livemode": false,
            "customer": "cus_fixture",
            "metadata": { "account_id": "account-1", "plan": "one_gb" },
            "items": {
                "has_more": false,
                "data": [{
                    "price": { "id": "price_ten_gb_fixture" },
                    "quantity": 1,
                    "current_period_end": 4_102_444_800_i64
                }]
            },
            "cancel_at_period_end": false
        }))
        .unwrap();

        validate_subscription(
            stripe,
            "account-1",
            Plan::TenGb,
            "cus_fixture",
            &subscription,
        )
        .unwrap();
        assert_eq!(
            subscription.items.data[0].current_period_end,
            Some(4_102_444_800)
        );
    }

    #[test]
    fn recurring_invoice_exposes_its_subscription_binding() {
        let invoice_payment: StripeInvoicePayment = serde_json::from_value(serde_json::json!({
            "id": "inpay_fixture",
            "invoice": "in_fixture",
            "livemode": false,
            "currency": "usd",
            "status": "paid",
            "payment": {
                "type": "payment_intent",
                "payment_intent": "pi_fixture"
            }
        }))
        .unwrap();
        assert_eq!(invoice_payment.invoice.id(), "in_fixture");
        assert_eq!(
            invoice_payment
                .payment
                .payment_intent
                .as_ref()
                .map(Expandable::id),
            Some("pi_fixture")
        );
        let invoice: StripeInvoice = serde_json::from_value(serde_json::json!({
            "id": "in_fixture",
            "livemode": false,
            "currency": "usd",
            "customer": "cus_fixture",
            "parent": {
                "type": "subscription_details",
                "subscription_details": { "subscription": "sub_fixture" }
            }
        }))
        .unwrap();
        let subscription_id = invoice
            .parent
            .as_ref()
            .filter(|parent| parent.kind == "subscription_details")
            .and_then(|parent| parent.subscription_details.as_ref())
            .map(|details| details.subscription.id());
        assert_eq!(subscription_id, Some("sub_fixture"));
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
                credit_price_id: "price_fixture".to_owned(),
                one_gb_price_id: Some("price_one_gb_fixture".to_owned()),
                ten_gb_price_id: Some("price_ten_gb_fixture".to_owned()),
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
        NotaryAdmissionConfig, SESSION_COOKIE, fresh_database, insert_test_github_user, sha256_hex,
        tests::test_registry,
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
            "amount_total": 2 * CENTS_PER_GB,
            "currency": "usd",
            "client_reference_id": purchase_id,
            "metadata": { "purchase_id": purchase_id, "schema_version": "1" },
            "customer": if paid { serde_json::json!({ "id": "cus_fixture" }) } else { Value::Null },
            "payment_intent": if paid {
                serde_json::json!({
                    "id": "pi_fixture",
                    "amount_received": 2 * CENTS_PER_GB,
                    "currency": "usd",
                    "metadata": { "purchase_id": payment_intent_purchase_id },
                    "latest_charge": { "id": "ch_fixture", "amount": 2 * CENTS_PER_GB,
                        "amount_refunded": 0, "currency": "usd", "livemode": false,
                        "payment_intent": "pi_fixture" }
                })
            } else { Value::Null },
            "line_items": if paid {
                serde_json::json!({
                    "has_more": false,
                    "data": [{ "amount_total": 2 * CENTS_PER_GB, "currency": "usd", "quantity": 2,
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
            "amount": 2 * CENTS_PER_GB,
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
            "amount_received": 2 * CENTS_PER_GB,
            "currency": "usd",
            "latest_charge": "ch_fixture",
            "metadata": { "purchase_id": purchase_id }
        }))
    }

    async fn mock_invoice_payments() -> Json<Value> {
        Json(serde_json::json!({
            "object": "list",
            "has_more": false,
            "data": []
        }))
    }

    async fn test_state(billing: BillingService) -> NotaryApiState {
        let database = fresh_database().await;
        NotaryApiState {
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
            public_origin: Url::parse("https://example.test").unwrap(),
            secure_cookies: true,
            registry: test_registry(),
            traces: crate::traces::owner::TraceService::disabled_for_test(),
            admission: Arc::new(NotaryAdmissionConfig::for_test()),
            billing,
        }
    }

    async fn deliver_event(
        state: &NotaryApiState,
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
    async fn subscription_status_and_price_drive_the_account_plan() {
        let state = test_state(BillingService::disabled_for_test()).await;
        insert_test_github_user(&state.database, "subscriber", 89, "subscriber").await;
        let now = unix_timestamp().unwrap();
        let mut subscription: StripeSubscription = serde_json::from_value(serde_json::json!({
            "id": "sub_fixture",
            "status": "active",
            "livemode": false,
            "customer": "cus_fixture",
            "metadata": { "account_id": "subscriber" },
            "items": {
                "has_more": false,
                "data": [{
                    "price": { "id": "price_one_gb_fixture" },
                    "quantity": 1,
                    "current_period_end": now + 2_592_000
                }]
            },
            "cancel_at_period_end": false
        }))
        .unwrap();

        store_subscription(&state, "subscriber", Plan::OneGb, &subscription, now)
            .await
            .unwrap();
        let active = crate::credits::account_billing_state(&state.database, "subscriber")
            .await
            .unwrap();
        assert_eq!(active.plan, Plan::OneGb);
        assert_eq!(active.billing_status, BillingStatus::Active);

        subscription.items.data[0].price.id = "price_ten_gb_fixture".to_owned();
        store_subscription(&state, "subscriber", Plan::TenGb, &subscription, now + 1)
            .await
            .unwrap();
        subscription.status = "past_due".to_owned();
        store_subscription(&state, "subscriber", Plan::TenGb, &subscription, now + 2)
            .await
            .unwrap();
        let review = crate::credits::account_billing_state(&state.database, "subscriber")
            .await
            .unwrap();
        assert_eq!(review.plan, Plan::TenGb);
        assert_eq!(review.billing_status, BillingStatus::Review);

        subscription.status = "canceled".to_owned();
        store_subscription(&state, "subscriber", Plan::TenGb, &subscription, now + 3)
            .await
            .unwrap();
        let canceled = crate::credits::account_billing_state(&state.database, "subscriber")
            .await
            .unwrap();
        assert_eq!(canceled.plan, Plan::Free);
        assert_eq!(canceled.billing_status, BillingStatus::Active);

        let replacement: StripeSubscription = serde_json::from_value(serde_json::json!({
            "id": "sub_replacement",
            "status": "active",
            "livemode": false,
            "customer": "cus_replacement",
            "metadata": { "account_id": "subscriber" },
            "items": {
                "has_more": false,
                "data": [{
                    "price": { "id": "price_one_gb_fixture" },
                    "quantity": 1,
                    "current_period_end": now + 5_184_000
                }]
            },
            "cancel_at_period_end": false
        }))
        .unwrap();
        store_subscription(&state, "subscriber", Plan::OneGb, &replacement, now + 4)
            .await
            .unwrap();
        // A delayed event for the canceled subscription updates its history,
        // not the replacement subscription that now owns the entitlement.
        store_subscription(&state, "subscriber", Plan::TenGb, &subscription, now + 5)
            .await
            .unwrap();
        let replaced = crate::credits::account_billing_state(&state.database, "subscriber")
            .await
            .unwrap();
        assert_eq!(replaced.plan, Plan::OneGb);
        assert_eq!(replaced.billing_status, BillingStatus::Active);
        let subscriptions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM billing_subscriptions WHERE account_id = 'subscriber'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(subscriptions, 2);
        assert_eq!(
            active_subscription_customer_id(&state.database, "subscriber")
                .await
                .unwrap()
                .as_deref(),
            Some("cus_replacement")
        );
        assert_eq!(
            preferred_customer_id(&state.database, "subscriber")
                .await
                .unwrap()
                .as_deref(),
            Some("cus_replacement")
        );

        sqlx::query(
            "INSERT INTO billing_subscription_disputes
                 (provider_dispute_id, provider_subscription_id, account_id,
                  provider_charge_id, amount_cents, currency, active, livemode,
                  created_at, updated_at)
             VALUES ('dp_subscription', 'sub_replacement', 'subscriber',
                     'ch_subscription', 999, 'usd', TRUE, FALSE, $1, $1)",
        )
        .bind(now + 6)
        .execute(&state.database)
        .await
        .unwrap();
        let mut transaction = state.database.begin().await.unwrap();
        recompute_account_billing_state(&mut transaction, "subscriber", now + 6)
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        let disputed = crate::credits::account_billing_state(&state.database, "subscriber")
            .await
            .unwrap();
        assert_eq!(disputed.plan, Plan::OneGb);
        assert_eq!(disputed.billing_status, BillingStatus::Review);
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
            .route("/v1/invoice_payments", get(mock_invoice_payments))
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
            "INSERT INTO browser_sessions (token_hash, account_id, expires_at, created_at)
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
            "SELECT COUNT(*) FROM credit_grants
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
             FROM credit_grants WHERE account_id = 'billing-user'
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
            "SELECT plan, billing_status FROM account_billing_profiles
             WHERE account_id = 'billing-user'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(profile, ("free".to_owned(), "review".to_owned()));

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
            "SELECT plan, billing_status FROM account_billing_profiles
             WHERE account_id = 'billing-user'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(profile, ("free".to_owned(), "active".to_owned()));

        mock.lock().unwrap().amount_refunded = 2 * CENTS_PER_GB;
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
            "SELECT plan, billing_status FROM account_billing_profiles
             WHERE account_id = 'billing-user'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(profile, ("free".to_owned(), "active".to_owned()));
        let adjustments: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(amount_bytes), 0)::BIGINT
             FROM credit_adjustments WHERE account_id = 'billing-user'",
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
            "SELECT outcome FROM stripe_webhook_events WHERE id = 'evt_wrong_environment'",
        )
        .fetch_one(&state.database)
        .await
        .unwrap();
        assert_eq!(event_outcome, "rejected");
    }
}
