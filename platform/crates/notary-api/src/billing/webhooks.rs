use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use super::super::{ApiError, ApiResult, NotaryApiState, unix_timestamp};
use super::{store::*, stripe::*};

const MAX_WEBHOOK_BYTES: usize = 1 << 20;
const WEBHOOK_TOLERANCE_SECS: i64 = 5 * 60;
pub(super) type HmacSha256 = Hmac<Sha256>;

pub(super) async fn handle_stripe_webhook(
    State(state): State<NotaryApiState>,
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
            if session.metadata.get("billing_kind").map(String::as_str) == Some("subscription") {
                process_subscription_checkout_event(&state, &stripe, &event, session, now).await?;
            } else {
                process_checkout_event(&state, &stripe, &event, session, now).await?;
            }
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
            if session.metadata.get("billing_kind").map(String::as_str) == Some("subscription") {
                process_subscription_checkout_failure(&state, &event, &session, now).await?;
            } else {
                process_checkout_failure_event(&state, &event, session, now).await?;
            }
        }
        "customer.subscription.created"
        | "customer.subscription.updated"
        | "customer.subscription.deleted"
        | "customer.subscription.paused"
        | "customer.subscription.resumed" => {
            let Some(subscription_id) = object_id else {
                reject_event(&state.database, &event.id, "missing_object_id", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe subscription event has no object identifier",
                ));
            };
            let subscription = stripe
                .retrieve_subscription(&subscription_id)
                .await
                .map_err(stripe_api_error)?;
            if subscription.id != subscription_id {
                reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                return Err(ApiError::bad_request(
                    "Stripe subscription response identifier did not match the event",
                ));
            }
            reconcile_subscription(&state, &stripe, &event, &subscription, now).await?;
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
            if let Some(invoice_payment) = stripe
                .invoice_payment_for_payment_intent(payment_intent_id)
                .await
                .map_err(stripe_api_error)?
            {
                let invoice_id = invoice_payment.invoice.id();
                let invoice = stripe
                    .retrieve_invoice(invoice_id)
                    .await
                    .map_err(stripe_api_error)?;
                if invoice.id != invoice_id {
                    reject_event(&state.database, &event.id, "object_id_mismatch", now).await?;
                    return Err(ApiError::bad_request(
                        "Stripe Invoice response did not match the charge",
                    ));
                }
                process_subscription_dispute_event(
                    &state,
                    &stripe,
                    SubscriptionDisputeEvent {
                        event: &event,
                        dispute: &dispute,
                        charge: &charge,
                        payment_intent: &payment_intent,
                        invoice_payment: &invoice_payment,
                        invoice: &invoice,
                    },
                    now,
                )
                .await?;
            } else {
                process_dispute_event(&state, &event, &dispute, &charge, &payment_intent, now)
                    .await?;
            }
        }
        _ => {
            finish_event(&state.database, &event.id, "ignored", None, now).await?;
        }
    }
    Ok(StatusCode::OK)
}

pub(super) fn verify_webhook_signature(
    secret: &[u8],
    header: &str,
    body: &[u8],
    now: i64,
) -> ApiResult<()> {
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

pub(super) fn validate_event_envelope(event: &StripeEvent) -> ApiResult<()> {
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

pub(super) fn event_object_id(object: &Value) -> Option<String> {
    object
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 255)
        .map(str::to_owned)
}
