use anyhow::{Context, Result, anyhow, bail};
use axum::http::StatusCode;
use sqlx::{FromRow, Postgres, Transaction};

use super::super::{
    ApiError, ApiResult, DatabasePool, NotaryApiState,
    credits::{
        BillingStatus, Plan, PurchaseAdjustmentSpec, apply_purchase_adjustment,
        grant_external_purchase, set_account_billing_state,
    },
    database_error,
};
use super::stripe::*;
use super::{BillingPurchase, PurchaseState};

#[derive(FromRow)]
pub(super) struct PurchaseRow {
    pub(super) id: String,
    pub(super) account_id: String,
    pub(super) state: String,
    pub(super) currency: String,
    pub(super) unit_amount_cents: i64,
    pub(super) quantity_gb: i64,
    pub(super) credit_bytes: i64,
    pub(super) expected_amount_cents: i64,
    pub(super) provider_price_id: String,
    pub(super) provider_checkout_session_id: Option<String>,
    pub(super) provider_payment_intent_id: Option<String>,
    pub(super) provider_charge_id: Option<String>,
    pub(super) provider_dispute_id: Option<String>,
    pub(super) provider_customer_id: Option<String>,
    pub(super) livemode: bool,
    pub(super) amount_paid_cents: i64,
    pub(super) amount_refunded_cents: i64,
    pub(super) amount_disputed_cents: i64,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
    pub(super) paid_at: Option<i64>,
}

impl PurchaseRow {
    pub(super) fn public(&self) -> ApiResult<BillingPurchase> {
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

pub(super) const PURCHASE_COLUMNS: &str = "id, account_id, state, currency, unit_amount_cents,
     quantity_gb, credit_bytes, expected_amount_cents, provider_price_id,
     provider_checkout_session_id, provider_payment_intent_id, provider_charge_id,
     provider_dispute_id, provider_customer_id, livemode, amount_paid_cents,
     amount_refunded_cents, amount_disputed_cents, created_at, updated_at, paid_at";

pub(super) async fn bind_checkout_session(
    database: &DatabasePool,
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

pub(super) async fn preferred_customer_id(
    database: &DatabasePool,
    account_id: &str,
) -> ApiResult<Option<String>> {
    let subscription_customer = sqlx::query_scalar(
        "SELECT provider_customer_id FROM billing_subscriptions
         WHERE account_id = $1
         ORDER BY (status NOT IN ('canceled', 'incomplete_expired')) DESC,
                  updated_at DESC
         LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(database)
    .await
    .map_err(database_error)?;
    if subscription_customer.is_some() {
        return Ok(subscription_customer);
    }
    sqlx::query_scalar(
        "SELECT provider_customer_id FROM billing_purchases
         WHERE account_id = $1 AND provider_customer_id IS NOT NULL
         ORDER BY updated_at DESC, id DESC LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(database)
    .await
    .map_err(database_error)
}

pub(super) async fn active_subscription_customer_id(
    database: &DatabasePool,
    account_id: &str,
) -> ApiResult<Option<String>> {
    sqlx::query_scalar(
        "SELECT provider_customer_id FROM billing_subscriptions
         WHERE account_id = $1 AND status NOT IN ('canceled', 'incomplete_expired')
         ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(database)
    .await
    .map_err(database_error)
}

pub(super) async fn select_purchase_by_idempotency(
    database: &DatabasePool,
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

pub(super) async fn select_purchase(
    database: &DatabasePool,
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

pub(super) async fn register_event(
    database: &DatabasePool,
    event: &StripeEvent,
    object_id: Option<&str>,
    received_at: i64,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO stripe_webhook_events
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

pub(super) async fn event_already_finished(
    database: &DatabasePool,
    event_id: &str,
) -> ApiResult<bool> {
    sqlx::query_scalar::<_, Option<i64>>(
        "SELECT processed_at FROM stripe_webhook_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_one(database)
    .await
    .map_err(database_error)
    .map(|processed_at| processed_at.is_some())
}

pub(super) async fn finish_event(
    database: &DatabasePool,
    event_id: &str,
    outcome: &str,
    error_code: Option<&str>,
    processed_at: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE stripe_webhook_events
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

pub(super) async fn reject_event(
    database: &DatabasePool,
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

pub(super) async fn process_subscription_checkout_event(
    state: &NotaryApiState,
    stripe: &StripeClient,
    event: &StripeEvent,
    session: StripeCheckoutSession,
    now: i64,
) -> ApiResult<()> {
    let checkout_id = session
        .metadata
        .get("subscription_checkout_id")
        .filter(|value| {
            validate_internal_id(value, "invalid subscription checkout binding").is_ok()
        })
        .ok_or_else(|| ApiError::bad_request("Stripe subscription Checkout binding is invalid"))?;
    if session.mode.as_deref() != Some("subscription")
        || session.status.as_deref() != Some("complete")
        || session.client_reference_id.as_deref() != Some(checkout_id)
    {
        reject_event(&state.database, &event.id, "checkout_mismatch", now).await?;
        return Err(ApiError::bad_request(
            "Stripe subscription Checkout Session did not match the local checkout",
        ));
    }
    let subscription_id = session
        .subscription
        .as_ref()
        .map(Expandable::id)
        .ok_or_else(|| ApiError::bad_request("Stripe Checkout has no subscription"))?;
    let customer_id = session
        .customer
        .as_ref()
        .map(Expandable::id)
        .ok_or_else(|| ApiError::bad_request("Stripe Checkout has no customer"))?;
    validate_stripe_id(subscription_id, "sub_").map_err(stripe_invalid_error)?;
    validate_stripe_id(customer_id, "cus_").map_err(stripe_invalid_error)?;
    let row = sqlx::query_as::<_, (String, String, String, String, bool, Option<String>)>(
        "SELECT account_id, target_plan, state, provider_price_id, livemode,
                provider_checkout_session_id
         FROM billing_subscription_checkouts WHERE id = $1",
    )
    .bind(checkout_id)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?
    .ok_or_else(|| ApiError::bad_request("Stripe subscription Checkout is not recognized"))?;
    let plan = parse_subscription_plan(&row.1)?;
    if row.2 != "checkout_open"
        || row.3
            != stripe
                .subscription_price_id(plan)
                .map_err(stripe_invalid_error)?
        || row.4 != stripe.livemode
        || row.5.as_deref() != Some(&session.id)
    {
        reject_event(&state.database, &event.id, "checkout_mismatch", now).await?;
        return Err(ApiError::bad_request(
            "Stripe subscription Checkout Session did not match the local checkout",
        ));
    }
    let subscription = stripe
        .retrieve_subscription(subscription_id)
        .await
        .map_err(stripe_api_error)?;
    validate_subscription(stripe, &row.0, plan, customer_id, &subscription)?;
    store_subscription(state, &row.0, plan, &subscription, now).await?;
    sqlx::query(
        "UPDATE billing_subscription_checkouts
         SET state = 'completed', provider_customer_id = $1,
             provider_subscription_id = $2, updated_at = $3
         WHERE id = $4 AND state = 'checkout_open'",
    )
    .bind(customer_id)
    .bind(subscription_id)
    .bind(now)
    .bind(checkout_id)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    finish_event(&state.database, &event.id, "processed", None, now).await
}

pub(super) async fn process_subscription_checkout_failure(
    state: &NotaryApiState,
    event: &StripeEvent,
    session: &StripeCheckoutSession,
    now: i64,
) -> ApiResult<()> {
    let checkout_id = session
        .metadata
        .get("subscription_checkout_id")
        .ok_or_else(|| ApiError::bad_request("Stripe subscription Checkout binding is missing"))?;
    sqlx::query(
        "UPDATE billing_subscription_checkouts SET state = 'expired', updated_at = $1
         WHERE id = $2 AND provider_checkout_session_id = $3 AND state = 'checkout_open'",
    )
    .bind(now)
    .bind(checkout_id)
    .bind(&session.id)
    .execute(&state.database)
    .await
    .map_err(database_error)?;
    finish_event(&state.database, &event.id, "processed", None, now).await
}

pub(super) async fn reconcile_subscription(
    state: &NotaryApiState,
    stripe: &StripeClient,
    event: &StripeEvent,
    subscription: &StripeSubscription,
    now: i64,
) -> ApiResult<()> {
    let existing_account: Option<String> = sqlx::query_scalar(
        "SELECT account_id FROM billing_subscriptions WHERE provider_subscription_id = $1",
    )
    .bind(&subscription.id)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;
    let account_id = existing_account
        .or_else(|| subscription.metadata.get("account_id").cloned())
        .ok_or_else(|| ApiError::bad_request("Stripe subscription has no account binding"))?;
    let price_id = subscription_price(subscription)?;
    let plan = plan_for_price(stripe, price_id)?;
    validate_subscription(
        stripe,
        &account_id,
        plan,
        subscription.customer.id(),
        subscription,
    )?;
    store_subscription(state, &account_id, plan, subscription, now).await?;
    finish_event(&state.database, &event.id, "processed", None, now).await
}

pub(super) fn validate_subscription(
    stripe: &StripeClient,
    account_id: &str,
    plan: Plan,
    customer_id: &str,
    subscription: &StripeSubscription,
) -> ApiResult<()> {
    validate_stripe_id(&subscription.id, "sub_").map_err(stripe_invalid_error)?;
    validate_stripe_id(customer_id, "cus_").map_err(stripe_invalid_error)?;
    if subscription.livemode != stripe.livemode
        || subscription.customer.id() != customer_id
        || subscription.metadata.get("account_id").map(String::as_str) != Some(account_id)
        || !matches!(
            subscription.status.as_str(),
            "trialing"
                | "active"
                | "past_due"
                | "paused"
                | "unpaid"
                | "canceled"
                | "incomplete"
                | "incomplete_expired"
        )
        || subscription_price(subscription)?
            != stripe
                .subscription_price_id(plan)
                .map_err(stripe_invalid_error)?
    {
        return Err(stripe_invalid(
            "Stripe subscription did not match the local plan",
        ));
    }
    Ok(())
}

pub(super) fn subscription_price(subscription: &StripeSubscription) -> ApiResult<&str> {
    if subscription.items.has_more || subscription.items.data.len() != 1 {
        return Err(stripe_invalid(
            "Stripe subscription must contain exactly one item",
        ));
    }
    let item = &subscription.items.data[0];
    if item.quantity != Some(1) {
        return Err(stripe_invalid("Stripe subscription quantity must be one"));
    }
    Ok(&item.price.id)
}

pub(super) fn plan_for_price(stripe: &StripeClient, price_id: &str) -> ApiResult<Plan> {
    if stripe.one_gb_price_id.as_deref() == Some(price_id) {
        Ok(Plan::OneGb)
    } else if stripe.ten_gb_price_id.as_deref() == Some(price_id) {
        Ok(Plan::TenGb)
    } else {
        Err(stripe_invalid("Stripe subscription uses an unknown Price"))
    }
}

pub(super) fn parse_subscription_plan(value: &str) -> ApiResult<Plan> {
    match value {
        "one_gb" => Ok(Plan::OneGb),
        "ten_gb" => Ok(Plan::TenGb),
        _ => Err(ApiError::internal(anyhow!("invalid subscription plan"))),
    }
}

pub(super) async fn store_subscription(
    state: &NotaryApiState,
    account_id: &str,
    plan: Plan,
    subscription: &StripeSubscription,
    now: i64,
) -> ApiResult<()> {
    let price_id = subscription_price(subscription)?;
    let current_period_end = subscription
        .items
        .data
        .first()
        .and_then(|item| item.current_period_end);
    let mut transaction = state.database.begin().await.map_err(database_error)?;
    let stored = sqlx::query(
        "INSERT INTO billing_subscriptions
             (provider_subscription_id, account_id, provider, provider_customer_id,
              provider_price_id, plan, status, livemode, current_period_end,
              cancel_at_period_end, created_at, updated_at)
         VALUES ($2, $1, 'stripe', $3, $4, $5, $6, $7, $8, $9, $10, $10)
         ON CONFLICT (provider_subscription_id) DO UPDATE
         SET provider_customer_id = EXCLUDED.provider_customer_id,
             provider_price_id = EXCLUDED.provider_price_id,
             plan = EXCLUDED.plan,
             status = EXCLUDED.status,
             livemode = EXCLUDED.livemode,
             current_period_end = EXCLUDED.current_period_end,
             cancel_at_period_end = EXCLUDED.cancel_at_period_end,
             updated_at = EXCLUDED.updated_at
         WHERE billing_subscriptions.account_id = EXCLUDED.account_id",
    )
    .bind(account_id)
    .bind(&subscription.id)
    .bind(subscription.customer.id())
    .bind(price_id)
    .bind(plan.as_str())
    .bind(&subscription.status)
    .bind(subscription.livemode)
    .bind(current_period_end)
    .bind(subscription.cancel_at_period_end)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if stored.rows_affected() != 1 {
        return Err(ApiError::bad_request(
            "Stripe subscription is already bound to another account",
        ));
    }
    recompute_account_billing_state(&mut transaction, account_id, now).await?;
    transaction.commit().await.map_err(database_error)
}

pub(super) async fn process_checkout_failure_event(
    state: &NotaryApiState,
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

pub(super) struct CheckoutPayment {
    pub(super) payment_intent_id: String,
    pub(super) charge_id: String,
    pub(super) customer_id: Option<String>,
}

pub(super) async fn process_checkout_event(
    state: &NotaryApiState,
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

pub(super) fn validate_paid_session(
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

pub(super) async fn process_refund_event(
    state: &NotaryApiState,
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

pub(super) async fn process_dispute_event(
    state: &NotaryApiState,
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

pub(super) struct SubscriptionDisputeEvent<'a> {
    pub(super) event: &'a StripeEvent,
    pub(super) dispute: &'a StripeDispute,
    pub(super) charge: &'a StripeCharge,
    pub(super) payment_intent: &'a StripePaymentIntent,
    pub(super) invoice_payment: &'a StripeInvoicePayment,
    pub(super) invoice: &'a StripeInvoice,
}

pub(super) async fn process_subscription_dispute_event(
    state: &NotaryApiState,
    stripe: &StripeClient,
    dispute_event: SubscriptionDisputeEvent<'_>,
    now: i64,
) -> ApiResult<()> {
    let SubscriptionDisputeEvent {
        event,
        dispute,
        charge,
        payment_intent,
        invoice_payment,
        invoice,
    } = dispute_event;
    let active = match (dispute.status.as_str(), event.event_type.as_str()) {
        ("won", _) => false,
        ("lost", _) => true,
        (_, "charge.dispute.funds_withdrawn") => true,
        (_, "charge.dispute.funds_reinstated") => false,
        _ => {
            finish_event(&state.database, &event.id, "ignored", None, now).await?;
            return Ok(());
        }
    };
    let subscription_id = invoice
        .parent
        .as_ref()
        .filter(|parent| parent.kind == "subscription_details")
        .and_then(|parent| parent.subscription_details.as_ref())
        .map(|details| details.subscription.id())
        .ok_or_else(|| ApiError::bad_request("Stripe Invoice has no subscription binding"))?;
    validate_stripe_id(subscription_id, "sub_").map_err(stripe_invalid_error)?;
    let subscription = stripe
        .retrieve_subscription(subscription_id)
        .await
        .map_err(stripe_api_error)?;
    if subscription.id != subscription_id {
        reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
        return Err(ApiError::bad_request(
            "Stripe Subscription response did not match the Invoice",
        ));
    }
    let existing_account: Option<String> = sqlx::query_scalar(
        "SELECT account_id FROM billing_subscriptions WHERE provider_subscription_id = $1",
    )
    .bind(subscription_id)
    .fetch_optional(&state.database)
    .await
    .map_err(database_error)?;
    let account_id = existing_account
        .or_else(|| subscription.metadata.get("account_id").cloned())
        .ok_or_else(|| ApiError::bad_request("Stripe subscription has no account binding"))?;
    let plan = plan_for_price(stripe, subscription_price(&subscription)?)?;
    validate_subscription(
        stripe,
        &account_id,
        plan,
        invoice.customer.id(),
        &subscription,
    )?;
    let valid = event.livemode == stripe.livemode
        && invoice_payment.livemode == event.livemode
        && invoice_payment.currency == "usd"
        && invoice_payment.status == "paid"
        && invoice_payment.invoice.id() == invoice.id
        && invoice_payment.payment.kind == "payment_intent"
        && invoice_payment
            .payment
            .payment_intent
            .as_ref()
            .map(Expandable::id)
            == Some(payment_intent.id.as_str())
        && invoice.livemode == event.livemode
        && invoice.currency == "usd"
        && charge.livemode == event.livemode
        && charge.payment_intent.as_deref() == Some(payment_intent.id.as_str())
        && charge.currency == invoice.currency
        && charge.amount > 0
        && dispute.currency == invoice.currency
        && dispute.amount > 0
        && dispute.amount <= charge.amount;
    if !valid {
        reject_event(
            &state.database,
            &event.id,
            "subscription_dispute_mismatch",
            now,
        )
        .await?;
        return Err(ApiError::bad_request(
            "Stripe dispute did not match the subscription Invoice",
        ));
    }
    store_subscription(state, &account_id, plan, &subscription, now).await?;

    let mut transaction = state.database.begin().await.map_err(database_error)?;
    if !lock_pending_event(&mut transaction, &event.id).await? {
        transaction.commit().await.map_err(database_error)?;
        return Ok(());
    }
    let stored = sqlx::query(
        "INSERT INTO billing_subscription_disputes
             (provider_dispute_id, provider_subscription_id, account_id,
              provider_charge_id, amount_cents, currency, active, livemode,
              created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (provider_dispute_id) DO UPDATE
         SET active = EXCLUDED.active, updated_at = EXCLUDED.updated_at
         WHERE billing_subscription_disputes.provider_subscription_id =
                   EXCLUDED.provider_subscription_id
           AND billing_subscription_disputes.account_id = EXCLUDED.account_id
           AND billing_subscription_disputes.provider_charge_id = EXCLUDED.provider_charge_id
           AND billing_subscription_disputes.amount_cents = EXCLUDED.amount_cents
           AND billing_subscription_disputes.currency = EXCLUDED.currency
           AND billing_subscription_disputes.livemode = EXCLUDED.livemode",
    )
    .bind(&dispute.id)
    .bind(subscription_id)
    .bind(&account_id)
    .bind(&charge.id)
    .bind(dispute.amount)
    .bind(&dispute.currency)
    .bind(active)
    .bind(event.livemode)
    .bind(event.created)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(database_error)?;
    if stored.rows_affected() != 1 {
        finish_event_transaction(
            &mut transaction,
            &event.id,
            "rejected",
            Some("subscription_dispute_mismatch"),
            now,
        )
        .await?;
        transaction.commit().await.map_err(database_error)?;
        return Err(ApiError::bad_request(
            "Stripe dispute changed its subscription binding",
        ));
    }
    recompute_account_billing_state(&mut transaction, &account_id, now).await?;
    finish_event_transaction(&mut transaction, &event.id, "processed", None, now).await?;
    transaction.commit().await.map_err(database_error)
}

pub(super) async fn lock_pending_event(
    transaction: &mut Transaction<'_, Postgres>,
    event_id: &str,
) -> ApiResult<bool> {
    let processed_at = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT processed_at FROM stripe_webhook_events WHERE id = $1 FOR UPDATE",
    )
    .bind(event_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?
    .ok_or_else(|| ApiError::internal(anyhow!("billing event registration was not durable")))?;
    Ok(processed_at.is_none())
}

pub(super) async fn finish_event_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    event_id: &str,
    outcome: &str,
    error_code: Option<&str>,
    processed_at: i64,
) -> ApiResult<()> {
    sqlx::query(
        "UPDATE stripe_webhook_events
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

pub(super) async fn select_purchase_for_update(
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

pub(super) async fn select_purchase_by_charge_for_update(
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

pub(super) async fn local_purchase_dependency_pending(
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

pub(super) async fn recompute_account_billing_state(
    transaction: &mut Transaction<'_, Postgres>,
    account_id: &str,
    updated_at: i64,
) -> ApiResult<()> {
    let has_dispute = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
                    SELECT 1 FROM billing_purchases
                    WHERE account_id = $1 AND amount_disputed_cents > 0
                    UNION ALL
                    SELECT 1 FROM billing_subscription_disputes
                    WHERE account_id = $1 AND active
                )",
    )
    .bind(account_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(database_error)?;
    let subscription = sqlx::query_as::<_, (String, String)>(
        "SELECT plan, status FROM billing_subscriptions
         WHERE account_id = $1 AND status NOT IN ('canceled', 'incomplete_expired')
         ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(account_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(database_error)?;
    let (plan, subscription_review) = match subscription.as_ref() {
        None => (Plan::Free, false),
        Some((plan, status)) => {
            let plan = match plan.as_str() {
                "one_gb" => Plan::OneGb,
                "ten_gb" => Plan::TenGb,
                _ => {
                    return Err(ApiError::internal(anyhow!(
                        "invalid subscription service plan"
                    )));
                }
            };
            let review = match status.as_str() {
                "active" | "trialing" => false,
                "past_due" | "paused" | "unpaid" | "incomplete" => true,
                _ => {
                    return Err(ApiError::internal(anyhow!("invalid subscription status")));
                }
            };
            (plan, review)
        }
    };
    set_account_billing_state(
        transaction,
        account_id,
        plan,
        if has_dispute || subscription_review {
            BillingStatus::Review
        } else {
            BillingStatus::Active
        },
        updated_at,
    )
    .await
}

pub(super) fn purchase_state_after_adjustment(
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

pub(super) fn cents_to_bytes(cents: i64) -> ApiResult<i64> {
    cents
        .checked_mul(BYTES_PER_CENT)
        .ok_or_else(|| ApiError::internal(anyhow!("billing credit adjustment overflow")))
}

pub(super) fn billing_dependency_pending() -> ApiError {
    ApiError::coded(
        StatusCode::SERVICE_UNAVAILABLE,
        "billing_event_dependency_pending",
        "A prerequisite Stripe event has not been processed yet",
    )
}
