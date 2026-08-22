use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use super::super::{ApiError, ApiResult, StripeConfig, credits::Plan};
use super::{CreateCheckoutSessionRequest, store::PurchaseRow};

pub(super) const BYTES_PER_GB: i64 = 1_000_000_000;
pub(super) const CENTS_PER_GB: i64 = 1_000;
pub(super) const BYTES_PER_CENT: i64 = BYTES_PER_GB / CENTS_PER_GB;
const MAX_QUANTITY_GB: i64 = 20;
pub(super) const STRIPE_API_VERSION: &str = "2026-02-25.clover";
const STRIPE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(super) struct StripeClient {
    pub(super) http: reqwest::Client,
    pub(super) api_base: Url,
    pub(super) secret_key: Arc<str>,
    pub(super) webhook_secret: Arc<str>,
    pub(super) credit_price_id: Arc<str>,
    pub(super) one_gb_price_id: Option<Arc<str>>,
    pub(super) ten_gb_price_id: Option<Arc<str>>,
    pub(super) livemode: bool,
    pub(super) allow_local_checkout_url: bool,
    pub(super) request_timeout: Duration,
}

impl StripeClient {
    pub(super) fn new(
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
            credit_price_id: Arc::from(config.credit_price_id),
            one_gb_price_id: config.one_gb_price_id.map(Arc::from),
            ten_gb_price_id: config.ten_gb_price_id.map(Arc::from),
            livemode: config.livemode,
            allow_local_checkout_url,
            request_timeout: STRIPE_REQUEST_TIMEOUT,
        })
    }

    pub(super) async fn retrieve_configured_price(&self) -> Result<StripeConfiguredPrice> {
        self.retrieve_object("prices", self.credit_price_id.as_ref(), "price_")
            .await
    }

    pub(super) fn subscription_price_id(&self, plan: Plan) -> Result<&str> {
        match plan {
            Plan::OneGb => self
                .one_gb_price_id
                .as_deref()
                .ok_or_else(|| anyhow!("the 1 GB Stripe Price is not configured")),
            Plan::TenGb => self
                .ten_gb_price_id
                .as_deref()
                .ok_or_else(|| anyhow!("the 10 GB Stripe Price is not configured")),
            Plan::Free => bail!("the Free plan has no Stripe Price"),
        }
    }

    pub(super) fn subscriptions_configured(&self) -> bool {
        self.one_gb_price_id.is_some() && self.ten_gb_price_id.is_some()
    }

    pub(super) async fn retrieve_subscription_price(
        &self,
        plan: Plan,
    ) -> Result<StripeConfiguredPrice> {
        self.retrieve_object("prices", self.subscription_price_id(plan)?, "price_")
            .await
    }

    pub(super) async fn create_subscription_checkout_session(
        &self,
        checkout_id: &str,
        account_id: &str,
        plan: Plan,
        customer_id: Option<&str>,
        success_url: &Url,
        cancel_url: &Url,
    ) -> Result<StripeCheckoutSession> {
        let mut form = vec![
            ("mode", "subscription".to_owned()),
            ("success_url", success_url.as_str().to_owned()),
            ("cancel_url", cancel_url.as_str().to_owned()),
            ("client_reference_id", checkout_id.to_owned()),
            ("metadata[billing_kind]", "subscription".to_owned()),
            ("metadata[subscription_checkout_id]", checkout_id.to_owned()),
            ("metadata[schema_version]", "2".to_owned()),
            (
                "subscription_data[metadata][account_id]",
                account_id.to_owned(),
            ),
            (
                "subscription_data[metadata][plan]",
                plan.as_str().to_owned(),
            ),
            (
                "line_items[0][price]",
                self.subscription_price_id(plan)?.to_owned(),
            ),
            ("line_items[0][quantity]", "1".to_owned()),
        ];
        if let Some(customer_id) = customer_id {
            validate_stripe_id(customer_id, "cus_")?;
            form.push(("customer", customer_id.to_owned()));
        }
        let url = self.api_base.join("checkout/sessions")?;
        self.send_json(
            self.http
                .post(url)
                .header("Stripe-Version", STRIPE_API_VERSION)
                .header(
                    "Idempotency-Key",
                    format!("subscription-checkout:{checkout_id}"),
                )
                .bearer_auth(self.secret_key.as_ref())
                .form(&form),
        )
        .await
    }

    pub(super) async fn retrieve_subscription(&self, id: &str) -> Result<StripeSubscription> {
        self.retrieve_object("subscriptions", id, "sub_").await
    }

    pub(super) async fn retrieve_invoice(&self, id: &str) -> Result<StripeInvoice> {
        self.retrieve_object("invoices", id, "in_").await
    }

    pub(super) async fn invoice_payment_for_payment_intent(
        &self,
        payment_intent_id: &str,
    ) -> Result<Option<StripeInvoicePayment>> {
        validate_stripe_id(payment_intent_id, "pi_")?;
        let mut url = self.api_base.join("invoice_payments")?;
        url.query_pairs_mut()
            .append_pair("payment[type]", "payment_intent")
            .append_pair("payment[payment_intent]", payment_intent_id)
            .append_pair("limit", "2");
        let mut payments: StripeList<StripeInvoicePayment> = self
            .send_json(
                self.http
                    .get(url)
                    .header("Stripe-Version", STRIPE_API_VERSION)
                    .bearer_auth(self.secret_key.as_ref()),
            )
            .await?;
        if payments.has_more || payments.data.len() > 1 {
            bail!("Stripe PaymentIntent is associated with multiple Invoices");
        }
        let payment = payments.data.pop();
        if let Some(payment) = payment.as_ref() {
            validate_stripe_id(&payment.id, "inpay_")?;
            if payment.payment.kind != "payment_intent"
                || payment.payment.payment_intent.as_ref().map(Expandable::id)
                    != Some(payment_intent_id)
            {
                bail!("Stripe InvoicePayment did not match the PaymentIntent filter");
            }
        }
        Ok(payment)
    }

    pub(super) async fn create_portal_session(
        &self,
        customer_id: &str,
        return_url: &Url,
    ) -> Result<StripePortalSession> {
        validate_stripe_id(customer_id, "cus_")?;
        let url = self.api_base.join("billing_portal/sessions")?;
        self.send_json(
            self.http
                .post(url)
                .header("Stripe-Version", STRIPE_API_VERSION)
                .bearer_auth(self.secret_key.as_ref())
                .form(&[
                    ("customer", customer_id),
                    ("return_url", return_url.as_str()),
                ]),
        )
        .await
    }

    pub(super) async fn create_checkout_session(
        &self,
        purchase_id: &str,
        quantity_gb: i64,
        customer_id: Option<&str>,
        success_url: &Url,
        cancel_url: &Url,
    ) -> Result<StripeCheckoutSession> {
        let mut form = vec![
            ("mode", "payment".to_owned()),
            ("success_url", success_url.as_str().to_owned()),
            ("cancel_url", cancel_url.as_str().to_owned()),
            ("client_reference_id", purchase_id.to_owned()),
            ("metadata[purchase_id]", purchase_id.to_owned()),
            ("metadata[billing_kind]", "credits".to_owned()),
            ("metadata[schema_version]", "1".to_owned()),
            (
                "payment_intent_data[metadata][purchase_id]",
                purchase_id.to_owned(),
            ),
            ("line_items[0][price]", self.credit_price_id.to_string()),
            ("line_items[0][quantity]", quantity_gb.to_string()),
        ];
        if let Some(customer_id) = customer_id {
            validate_stripe_id(customer_id, "cus_")?;
            form.push(("customer", customer_id.to_owned()));
        }
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

    pub(super) async fn retrieve_checkout_session(
        &self,
        id: &str,
    ) -> Result<StripeCheckoutSession> {
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

    pub(super) async fn retrieve_refund(&self, id: &str) -> Result<StripeRefund> {
        self.retrieve_object("refunds", id, "re_").await
    }

    pub(super) async fn retrieve_charge(&self, id: &str) -> Result<StripeCharge> {
        self.retrieve_object("charges", id, "ch_").await
    }

    pub(super) async fn retrieve_payment_intent(&self, id: &str) -> Result<StripePaymentIntent> {
        self.retrieve_object("payment_intents", id, "pi_").await
    }

    pub(super) async fn retrieve_dispute(&self, id: &str) -> Result<StripeDispute> {
        self.retrieve_object("disputes", id, "dp_").await
    }

    pub(super) async fn retrieve_object<T: serde::de::DeserializeOwned>(
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

    pub(super) async fn send_json<T: serde::de::DeserializeOwned>(
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

    pub(super) fn validate_checkout_url(&self, value: &str) -> Result<Url> {
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

    pub(super) fn validate_portal_url(&self, value: &str) -> Result<Url> {
        let url = Url::parse(value).context("Stripe Billing Portal URL is invalid")?;
        let local = self.allow_local_checkout_url
            && url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost"));
        let stripe = url.scheme() == "https"
            && url
                .host_str()
                .is_some_and(|host| host == "billing.stripe.com");
        if !local && !stripe {
            bail!("Stripe Billing Portal URL has an unexpected origin");
        }
        Ok(url)
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeCheckoutSession {
    pub(super) id: String,
    pub(super) url: Option<String>,
    pub(super) mode: Option<String>,
    pub(super) status: Option<String>,
    pub(super) livemode: bool,
    pub(super) payment_status: String,
    pub(super) amount_total: Option<i64>,
    pub(super) currency: Option<String>,
    pub(super) client_reference_id: Option<String>,
    pub(super) metadata: BTreeMap<String, String>,
    pub(super) payment_intent: Option<Expandable<StripePaymentIntent>>,
    pub(super) subscription: Option<Expandable<StripeReference>>,
    pub(super) customer: Option<Expandable<StripeReference>>,
    pub(super) line_items: Option<StripeList<StripeLineItem>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum Expandable<T> {
    Id(String),
    Object(T),
}

impl<T> Expandable<T>
where
    T: StripeObject,
{
    pub(super) fn id(&self) -> &str {
        match self {
            Self::Id(id) => id,
            Self::Object(object) => object.id(),
        }
    }
}

pub(super) trait StripeObject {
    fn id(&self) -> &str;
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeReference {
    pub(super) id: String,
}

impl StripeObject for StripeReference {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct StripePaymentIntent {
    pub(super) id: String,
    pub(super) amount_received: i64,
    pub(super) currency: String,
    pub(super) latest_charge: Option<Expandable<StripeCharge>>,
    #[serde(default)]
    pub(super) metadata: BTreeMap<String, String>,
}

impl StripeObject for StripePaymentIntent {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeCharge {
    pub(super) id: String,
    pub(super) amount: i64,
    pub(super) amount_refunded: i64,
    pub(super) currency: String,
    pub(super) livemode: bool,
    pub(super) payment_intent: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeInvoice {
    pub(super) id: String,
    pub(super) livemode: bool,
    pub(super) currency: String,
    pub(super) customer: Expandable<StripeReference>,
    pub(super) parent: Option<StripeInvoiceParent>,
}

impl StripeObject for StripeInvoice {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeInvoiceParent {
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) subscription_details: Option<StripeInvoiceSubscriptionDetails>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeInvoiceSubscriptionDetails {
    pub(super) subscription: Expandable<StripeReference>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeInvoicePayment {
    pub(super) id: String,
    pub(super) invoice: Expandable<StripeReference>,
    pub(super) livemode: bool,
    pub(super) currency: String,
    pub(super) status: String,
    pub(super) payment: StripeInvoicePaymentSource,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeInvoicePaymentSource {
    #[serde(rename = "type")]
    pub(super) kind: String,
    pub(super) payment_intent: Option<Expandable<StripeReference>>,
}

impl StripeObject for StripeCharge {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeRefund {
    pub(super) id: String,
    pub(super) amount: i64,
    pub(super) currency: String,
    pub(super) status: Option<String>,
    pub(super) charge: Option<String>,
    pub(super) payment_intent: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeDispute {
    pub(super) id: String,
    pub(super) amount: i64,
    pub(super) currency: String,
    pub(super) charge: String,
    pub(super) status: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeList<T> {
    pub(super) data: Vec<T>,
    pub(super) has_more: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeLineItem {
    pub(super) amount_total: i64,
    pub(super) currency: String,
    pub(super) quantity: Option<i64>,
    pub(super) price: Option<StripePrice>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripePrice {
    pub(super) id: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeConfiguredPrice {
    pub(super) id: String,
    pub(super) active: bool,
    pub(super) livemode: bool,
    pub(super) currency: String,
    pub(super) unit_amount: Option<i64>,
    pub(super) billing_scheme: String,
    #[serde(rename = "type")]
    pub(super) price_type: String,
    pub(super) custom_unit_amount: Option<Value>,
    pub(super) transform_quantity: Option<Value>,
    pub(super) recurring: Option<StripeRecurring>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeRecurring {
    pub(super) interval: String,
    pub(super) interval_count: i64,
    pub(super) usage_type: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeSubscription {
    pub(super) id: String,
    pub(super) status: String,
    pub(super) livemode: bool,
    pub(super) customer: Expandable<StripeReference>,
    pub(super) items: StripeList<StripeSubscriptionItem>,
    #[serde(default)]
    pub(super) metadata: BTreeMap<String, String>,
    #[serde(default)]
    pub(super) cancel_at_period_end: bool,
}

impl StripeObject for StripeSubscription {
    fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeSubscriptionItem {
    pub(super) price: StripePrice,
    pub(super) quantity: Option<i64>,
    pub(super) current_period_end: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripePortalSession {
    pub(super) id: String,
    pub(super) customer: Expandable<StripeReference>,
    pub(super) livemode: bool,
    pub(super) url: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeEvent {
    pub(super) id: String,
    pub(super) api_version: Option<String>,
    #[serde(rename = "type")]
    pub(super) event_type: String,
    pub(super) livemode: bool,
    pub(super) created: i64,
    pub(super) data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub(super) struct StripeEventData {
    pub(super) object: Value,
}

pub(super) fn validate_checkout_request(request: &CreateCheckoutSessionRequest) -> ApiResult<()> {
    if !(1..=MAX_QUANTITY_GB).contains(&request.quantity_gb) {
        return Err(ApiError::bad_request(
            "quantity_gb must be between 1 and 20",
        ));
    }
    validate_idempotency_key(&request.idempotency_key)
}

pub(super) fn validate_configured_price(
    stripe: &StripeClient,
    price: &StripeConfiguredPrice,
) -> Result<()> {
    validate_stripe_id(&price.id, "price_")?;
    if price.id != stripe.credit_price_id.as_ref()
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

pub(super) fn validate_subscription_price(
    stripe: &StripeClient,
    plan: Plan,
    price: &StripeConfiguredPrice,
) -> Result<()> {
    let expected_cents = match plan {
        Plan::OneGb => 999,
        Plan::TenGb => 4_999,
        Plan::Free => bail!("the Free plan has no subscription Price"),
    };
    let recurring = price.recurring.as_ref();
    if price.id != stripe.subscription_price_id(plan)?
        || !price.active
        || price.livemode != stripe.livemode
        || price.currency != "usd"
        || price.unit_amount != Some(expected_cents)
        || price.billing_scheme != "per_unit"
        || price.price_type != "recurring"
        || recurring.is_none_or(|recurring| {
            recurring.interval != "month"
                || recurring.interval_count != 1
                || recurring.usage_type != "licensed"
        })
        || price.custom_unit_amount.is_some()
        || price.transform_quantity.is_some()
    {
        bail!("configured subscription Price does not match the selected monthly USD plan");
    }
    Ok(())
}

pub(super) fn validate_idempotency_key(value: &str) -> ApiResult<()> {
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

pub(super) fn checkout_return_urls(
    public_origin: &Url,
    purchase_id: &str,
) -> ApiResult<(Url, Url)> {
    let build = |outcome: &str| -> ApiResult<Url> {
        let mut url = public_origin
            .join("account/usage")
            .map_err(|error| ApiError::internal(error.into()))?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("checkout", outcome)
            .append_pair("purchase_id", purchase_id)
            .finish();
        url.set_query(Some(&query));
        Ok(url)
    };
    let success = build("success")?;
    let cancel = build("cancelled")?;
    Ok((success, cancel))
}

pub(super) fn subscription_return_urls(public_origin: &Url) -> ApiResult<(Url, Url)> {
    let build = |outcome: &str| -> ApiResult<Url> {
        let mut url = public_origin
            .join("account/usage")
            .map_err(|error| ApiError::internal(error.into()))?;
        url.set_query(Some(&format!("subscription={outcome}")));
        Ok(url)
    };
    Ok((build("success")?, build("cancelled")?))
}

pub(super) fn validate_created_subscription_session(
    stripe: &StripeClient,
    checkout_id: &str,
    session: &StripeCheckoutSession,
) -> ApiResult<()> {
    validate_subscription_session_binding(stripe, checkout_id, session)?;
    if session.status.as_deref() != Some("open") {
        return Err(stripe_invalid("Stripe Checkout Session is not open"));
    }
    Ok(())
}

pub(super) fn validate_subscription_session_binding(
    stripe: &StripeClient,
    checkout_id: &str,
    session: &StripeCheckoutSession,
) -> ApiResult<()> {
    validate_stripe_id(&session.id, "cs_").map_err(stripe_invalid_error)?;
    if session.livemode != stripe.livemode
        || session.mode.as_deref() != Some("subscription")
        || session.client_reference_id.as_deref() != Some(checkout_id)
        || session.metadata.get("billing_kind").map(String::as_str) != Some("subscription")
        || session
            .metadata
            .get("subscription_checkout_id")
            .map(String::as_str)
            != Some(checkout_id)
        || session.metadata.get("schema_version").map(String::as_str) != Some("2")
    {
        return Err(stripe_invalid(
            "Stripe Checkout Session did not match the local subscription",
        ));
    }
    Ok(())
}

pub(super) fn validate_created_session(
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

pub(super) fn validate_internal_id(value: &str, message: &'static str) -> ApiResult<()> {
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

pub(super) fn validate_stripe_id(value: &str, prefix: &str) -> Result<()> {
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

pub(super) fn stripe_api_error(error: anyhow::Error) -> ApiError {
    tracing::warn!(%error, "Stripe API request failed");
    ApiError::coded(
        StatusCode::BAD_GATEWAY,
        "billing_provider_unavailable",
        "The payment provider is temporarily unavailable",
    )
}

pub(super) fn stripe_invalid(message: &'static str) -> ApiError {
    ApiError::coded(StatusCode::BAD_GATEWAY, "billing_provider_invalid", message)
}

pub(super) fn stripe_invalid_error(error: anyhow::Error) -> ApiError {
    tracing::warn!(%error, "Stripe returned an invalid billing response");
    stripe_invalid("The payment provider returned an invalid response")
}
