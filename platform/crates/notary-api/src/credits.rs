//! Credit plans, balances, history, offers, and entitlement policy.

use serde::Serialize;
use utoipa::ToSchema;

use crate::{admissions::AdmissionMode, config::NotaryAdmissionConfig};

#[derive(Clone, Copy, Debug, serde::Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Plan {
    Free,
    OneGb,
    TenGb,
}

impl Plan {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::OneGb => "one_gb",
            Self::TenGb => "ten_gb",
        }
    }
}

#[derive(Clone, Copy, Debug, serde::Deserialize, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CreditKind {
    Capture,
    Notarization,
}

impl CreditKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Capture => "capture",
            Self::Notarization => "notarization",
        }
    }

    pub(crate) fn for_mode(mode: AdmissionMode) -> Self {
        match mode {
            AdmissionMode::Capture => Self::Capture,
            AdmissionMode::Notarization => Self::Notarization,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BillingStatus {
    Active,
    Review,
}

impl BillingStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Review => "review",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
pub struct AccountBillingState {
    pub plan: Plan,
    pub billing_status: BillingStatus,
}

#[derive(Clone, Copy, Debug, Serialize, ToSchema, PartialEq, Eq)]
pub struct PlanEntitlements {
    pub monthly_notarization_bytes: i64,
    pub monthly_capture_bytes: i64,
    /// `None` means there is no fixed plan ceiling; abuse controls still apply.
    pub trace_storage_bytes: Option<i64>,
}

pub(crate) fn plan_entitlements(config: &NotaryAdmissionConfig, plan: Plan) -> PlanEntitlements {
    let policy = match plan {
        Plan::Free => &config.free,
        Plan::OneGb => &config.one_gb,
        Plan::TenGb => &config.ten_gb,
    };
    PlanEntitlements {
        monthly_notarization_bytes: policy.monthly_notarization_bytes,
        monthly_capture_bytes: policy.monthly_capture_bytes,
        trace_storage_bytes: match plan {
            Plan::Free => Some(1_000_000_000),
            Plan::OneGb => Some(10_000_000_000),
            Plan::TenGb => None,
        },
    }
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CreditHistoryKind {
    Grant,
    Debit,
    Adjustment,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditHistoryEntry {
    pub id: String,
    pub kind: CreditHistoryKind,
    pub credit_kind: CreditKind,
    pub amount_bytes: i64,
    pub source_kind: Option<String>,
    pub display_label: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditBalanceSummary {
    pub total_granted_bytes: i64,
    pub total_used_bytes: i64,
    pub total_remaining_bytes: i64,
    pub included_monthly_remaining_bytes: i64,
    pub supplemental_remaining_bytes: i64,
    pub next_grant_expiration: Option<i64>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditSummary {
    pub capture: CreditBalanceSummary,
    pub notarization: CreditBalanceSummary,
    pub reset_at: i64,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct CreditOffer {
    pub id: String,
    pub title: String,
    pub description: String,
    pub amount_bytes: i64,
    pub claim_expires_at: i64,
    pub credit_expires_at: i64,
}

#[derive(Serialize, ToSchema)]
pub struct CreditOffersResponse {
    pub offers: Vec<CreditOffer>,
}

#[derive(Serialize, ToSchema)]
pub struct ClaimCreditOfferResponse {
    pub offer_id: String,
    pub credits: CreditSummary,
}
