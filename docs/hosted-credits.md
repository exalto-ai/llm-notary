# Hosted finalization credits

Every signed-in hosted account is Free. There is no paid plan or account tier.
An account receives included monthly finalization credits and can add more
through purchases, promotions, or manual adjustments.

Credits are byte-denominated grants used only when a hosted finalization ticket
is redeemed. Adding or using them never changes proof strength, notary identity,
`.llmtrace` contents, verification, publication, sharing, downloads, or
self-hosted use. Capture itself consumes no credits. Finalization uses the
immutable authenticated TLS application-data allowance from the source bundle
receipt, not the size of the `.llmtrace` ZIP.

## Monthly and supplemental credits

The default monthly included grants are 64 MiB for anonymous Public use and
512 MiB for a signed-in Free account. They reset at the first instant of each
UTC month.

Supplemental grants are separate from monthly included credits. The hosted API
automatically gives every Free account one non-expiring 128 MiB testing grant.
It is labeled as testing credit in account history and uses a versioned source
reference so migration, sign-in, account refresh, and admission requests cannot
issue it twice. The API also offers an eligible account one server-defined,
one-time 128 MiB bonus. The browser sends only the offer identifier; the server
fixes the eligibility, amount, expiration, source, and per-account claim limit.
Manual adjustments and completed purchases use the same append-only grant
operation. There is no browser endpoint that accepts an arbitrary credit amount
or source; purchase settlement must create a server-authored `external_purchase`
grant.

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
allowance. Shared service-capacity limits still apply, but there is no
per-address session count, start-rate limit, or account-specific session
timeout.

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
`llm-notary whoami --json` report the same credit summary: total remaining,
included monthly remaining, additional remaining, monthly reset, next grant
expiration, and bounded grant/debit history. History labels and errors omit
address subjects, record digests, tickets, credentials, and other users'
activity.
