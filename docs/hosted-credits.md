# Plans and usage

Hosted accounts have separate monthly allowances for capture and notarization,
plus a limit on stored uploaded trace packages. These controls do not change
proof strength, notary identity, `.llmtrace` contents, verification, downloads,
or self-hosted use.

| Plan | Monthly capture | Monthly notarization | Trace storage | Price |
| --- | ---: | ---: | ---: | ---: |
| Free | 50 MB | 50 MB | 1 GB | $0 |
| 1 GB | 1 GB | 1 GB | 10 GB | $9.99/month |
| 10 GB | 10 GB | 10 GB | No fixed plan limit* | $49.99/month |

All units are decimal: one MB is 1,000,000 bytes and one GB is 1,000,000,000
bytes. Monthly allowances reset at the first instant of each UTC month and do
not roll over.

*Fair-use and abuse controls apply to the 10 GB plan's trace storage. Every plan
also keeps the platform's per-file package safety limit.

## What counts

Capture and notarization use independent ledgers. The API issues a short-lived
ticket only when the relevant allowance is positive. Redeeming the ticket
authorizes one operation; it does not reserve the account's remaining bytes or
create a renewable capacity lease. A capture ticket carries effective protocol
limits. A finalization ticket is additionally bound to the exact record digest
and authenticated byte allowance of its source capture.

Once admitted, an operation continues under the notary instance's local size,
concurrency, and timeout limits even if the API becomes unavailable. Usage
accounting is independent of the active session lifetime, and already-admitted
operations may put an account slightly over its allowance. The API denies the
next ticket until allowance is available again.

The expand/contract rollout temporarily retains the previous lease schema and
bridge-notary fallback for safe rollback. Only a redemption that omits the
`one_operation_v1` capability uses that legacy path; new operations do not
create, renew, or release capacity leases.

Trace storage is the total declared size of uploads that are in progress,
queued for checking, being checked, or admitted to the account. Rejected,
failed, expired, and purged uploads do not count. The API serializes concurrent
upload admissions per account so parallel requests cannot bypass the limit.

## Additional notarization

Every plan can buy 1–20 GB of additional notarization at $10 USD per decimal GB.
These one-time credits do not expire. The ledger consumes grants that expire
soonest before non-expiring purchased credits.
Additional credits do not increase capture or trace-storage allowances.

The browser chooses only a quantity and supplies an idempotency key. The API
fixes the currency, unit price, byte amount, Stripe Price, account, and payment
mode. Payment details are collected on Stripe-hosted Checkout and never pass
through LLM Notary.

Credits are granted only after a signed webhook is reconciled against the
current Checkout Session, its line item, PaymentIntent, and Charge. Duplicate
and out-of-order deliveries are safe. The platform stores provider identifiers
and processing outcomes, not raw webhook bodies, signatures, payment methods,
or customer details. Returning to the browser from Checkout cannot grant
credits.

A refund removes the corresponding fraction of purchased bytes. A dispute
temporarily removes disputed credit and puts hosted service under billing
review; reinstatement restores both. These changes use signed, append-only
activity entries.

Eligible accounts may also see a server-defined promotional notarization offer.
The browser sends only its identifier; the server fixes its eligibility, amount,
expiration, source, and claim limit.

## Subscriptions

New paid subscriptions start in Stripe-hosted Checkout. Existing paid accounts
use the Stripe Billing Portal to change plan, update payment details, or cancel.
The platform accepts a plan only when the Stripe Price is active, in the expected
test or live mode, billed monthly in USD, and exactly $9.99 or $49.99.

Only `active` and `trialing` subscriptions enable paid allowances. A
`past_due`, `paused`, `unpaid`, or `incomplete` subscription puts the account
under billing review and blocks new hosted captures, notarizations, and trace
uploads. A canceled or expired subscription returns the account to Free.

## Anonymous address scoping

Anonymous Public access uses the Free monthly capture and notarization
allowances without creating an account. The platform groups IPv4 by individual
address and IPv6 by `/64`, then derives a period-scoped opaque subject with a
versioned keyed HMAC. Credit, ticket, error, and metric records contain
only that opaque subject. The raw address is not sent to the notary and does not
enter evidence.

Address scoping is abuse control, not identity. Unrelated users behind one NAT
may share an allowance. A VPN, proxy, or address change may receive a different
allowance. Every notary instance independently enforces its configured local
resource and concurrency limits.

Forwarding headers are not trusted by default. The API accepts its dedicated
edge address header only when the immediate socket peer matches an explicitly
configured trusted proxy network. Direct and untrusted peers are scoped by the
socket address, so they cannot choose a subject with a forwarding header.

## Account and CLI views

The hosted account response, dashboard, local-service account response, and
`llm-notary whoami --json` report the same plan, billing status, separate capture
and notarization balances, reset date, and bounded activity history. The hosted
dashboard also shows current trace storage and subscription controls. History
labels and errors omit address subjects, record digests, tickets, credentials,
and other users' activity.

The native desktop app and local dashboard use the same account projection. They
show the account identity and sign-in provider, device or API-key mode, plan,
billing state, and credit details without exposing the hosted credential to the
browser or desktop renderer. Hosted account, usage, plan, and settings links are
constructed from the validated account origin. A local browser-approved device
session can be disconnected locally; API keys remain controlled by the hosted
account settings.

The account response reports whether Stripe is `disabled`, in `test` mode, or
`live`. The dashboard hides billing controls when Stripe is disabled and labels
test mode prominently.

## Operator configuration

Stripe support is disabled when all billing settings are absent. Enabling it
requires the complete set:

- `LLM_NOTARY_STRIPE_SECRET_KEY` or `LLM_NOTARY_STRIPE_SECRET_KEY_FILE`: an
  `sk_test_...` or `sk_live_...` key, supplied directly or through a private
  file, but never both.
- `LLM_NOTARY_STRIPE_WEBHOOK_SECRET` or
  `LLM_NOTARY_STRIPE_WEBHOOK_SECRET_FILE`: the matching endpoint's `whsec_...`
  signing secret, supplied directly or through a private file, but never both.
- `LLM_NOTARY_STRIPE_CREDIT_PRICE_ID`: the one-time $10/GB Price.
- `LLM_NOTARY_STRIPE_ONE_GB_PRICE_ID`: the recurring $9.99/month Price.
- `LLM_NOTARY_STRIPE_TEN_GB_PRICE_ID`: the recurring $49.99/month Price.

The webhook URL is `/api/billing/stripe/webhook` and its API version is pinned
to `2026-02-25.clover`. Configure these events:

- `checkout.session.completed`
- `checkout.session.async_payment_succeeded`
- `checkout.session.async_payment_failed`
- `checkout.session.expired`
- `customer.subscription.created`
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `customer.subscription.paused`
- `customer.subscription.resumed`
- `refund.created`, `refund.updated`, and `refund.failed`
- `charge.dispute.funds_withdrawn`, `charge.dispute.funds_reinstated`, and
  `charge.dispute.closed`

Test keys accept only test-mode Prices and events; live keys accept only
live-mode data. A publishable key is not required because all payment and
subscription screens are hosted by Stripe.
