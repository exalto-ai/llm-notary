# Credits and utilization

Every signed-in hosted account uses the same credit model. An account
receives included monthly finalization credits and can add more through
purchases, promotions, or manual adjustments.

Credits are byte-denominated grants used only when a hosted finalization ticket
is redeemed. Adding or using them never changes proof strength, notary identity,
`.llmtrace` contents, verification, publication, sharing, downloads, or
self-hosted use. Capture itself consumes no credits. Finalization uses the
immutable authenticated TLS application-data allowance from the source capture
receipt, not the size of the `.llmtrace` ZIP.

## Monthly and supplemental credits

The default monthly included grants are 64 MiB for anonymous Public use and
512 MiB for a signed-in account. They reset at the first instant of each
UTC month.

Supplemental grants are separate from monthly included credits. The hosted API
offers an eligible account one server-defined, one-time 128 MiB bonus. The
browser sends only the offer identifier; the server fixes the eligibility,
amount, expiration, source, and per-account claim limit. Previously issued
non-expiring testing grants remain usable, but the API no longer creates them.
Manual adjustments and completed purchases use the same append-only grant
operation. There is no browser endpoint that accepts an arbitrary credit amount
or source; purchase settlement must create a server-authored `external_purchase`
grant.

## Stripe purchases

The hosted dashboard sells one-time credit increments at a fixed price of
$5 USD per decimal GB (1,000,000,000 bytes). A purchase can contain 1–20 GB.
The browser chooses only the quantity and supplies an idempotency key; the API
fixes the currency, unit price, byte amount, Stripe Price, account, and payment
mode. Payment details are collected on Stripe-hosted Checkout and never pass
through LLM Notary.

Credits are granted only after a signed webhook is reconciled against the
current Checkout Session, its one line item, PaymentIntent, and Charge. Duplicate
and out-of-order deliveries are safe. The platform stores provider identifiers
and processing outcomes, not raw webhook bodies, signatures, payment methods,
or customer details. The browser's return from Checkout is only a status hint;
it cannot grant credits.

Purchased credits do not expire. A refund removes the corresponding fraction
of purchased bytes. A dispute temporarily removes disputed credit and places
hosted finalization under review; reinstatement restores both. These changes are
signed, append-only credit activity entries. A full refund returns the account
to the Free plan when it has no other unrefunded purchase.

Finalization debits consume grants that expire soonest, then grants without an
expiration. Each debit is allocated immutably to its source grants. Retrying
the same subject and bundle digest does not debit twice, and changing the
authenticated allowance on that retry is rejected.

## Anonymous address scoping

Anonymous Public access does not create an account. The platform groups IPv4
by individual address and IPv6 by `/64`, then derives a period-scoped opaque
subject with a versioned keyed HMAC. Credit, ticket, lease, error, and metric
records contain only that opaque subject. The raw address is not sent to the
notary and does not enter evidence.

Address scoping is abuse control, not identity. Unrelated users behind one NAT
may share an allowance. A VPN, proxy, or address change may receive a different
allowance. Shared service-capacity limits still apply.

Forwarding headers are not trusted by default. The API accepts its dedicated
edge address header only when the immediate socket peer matches an explicitly
configured trusted proxy network. Direct and untrusted peers are scoped by the
socket address, so they cannot choose a subject with a forwarding header.

Hosted admission keeps privacy-safe machine codes through the API, local
service, and notary handshake. Callers can distinguish exhausted credits and
offer eligibility without receiving an address subject, record digest, ticket,
or another customer's activity.

## Account and CLI views

The hosted account response, dashboard, local-service account response, and
`llm-notary whoami --json` report the same plan, billing status, and credit
summary: total remaining, included monthly remaining, additional remaining,
monthly reset, next grant expiration, and bounded grant/debit/adjustment
history. History labels and errors omit address subjects, record digests,
tickets, credentials, and other users' activity.

The hosted account response also reports whether purchases are `disabled`, in
Stripe `test` mode, or `live`. The dashboard hides Checkout controls when
purchases are disabled and labels test mode prominently; test Checkout never
represents a real charge.

## Operator configuration

Stripe support is disabled when all three settings are absent. Enabling it
requires the complete set:

- `LLM_NOTARY_STRIPE_SECRET_KEY` or `LLM_NOTARY_STRIPE_SECRET_KEY_FILE`: an
  `sk_test_...` or `sk_live_...` key, supplied directly or through a private
  file (but never both).
- `LLM_NOTARY_STRIPE_WEBHOOK_SECRET` or
  `LLM_NOTARY_STRIPE_WEBHOOK_SECRET_FILE`: the matching endpoint's `whsec_...`
  signing secret, supplied directly or through a private file (but never both).
- `LLM_NOTARY_STRIPE_PRICE_ID`: the single authoritative `price_...` identifier.

The webhook URL is `/api/billing/stripe/webhook` and its API version is pinned
to `2026-02-25.clover`. Test keys accept only test-mode Prices and events; live
keys accept only live-mode data. The publishable key is not required because
the dashboard redirects to Stripe-hosted Checkout rather than embedding Stripe
Elements.
