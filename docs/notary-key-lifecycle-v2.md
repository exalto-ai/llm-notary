# Notary key lifecycle v2

`GET /api/notary` publishes a versioned directory of notary endpoints and
secp256k1 verification keys. Clients cache successful responses so existing
evidence remains verifiable when a deployment changes keys.

## Directory format

```json
{
  "format": "llm-notary/notary-directory/v2",
  "active_key_id": "sha256:...",
  "notaries": [
    {
      "host": "203.0.113.10",
      "port": 7047,
      "key_id": "sha256:...",
      "public_key": "02...",
      "status": "active",
      "valid_from_unix_ms": 0,
      "valid_until_unix_ms": null
    }
  ]
}
```

The key ID is `sha256:` followed by the SHA-256 of the compressed SEC1 public
key. The API rejects malformed keys, duplicate IDs, inverted validity windows,
and an `active_key_id` that does not select an `active` record.

## Status semantics

| Status | New captures | Deferred finalization | Historical verification |
| --- | --- | --- | --- |
| `active` | yes | yes | within its validity window |
| `retiring` | no | yes, during the overlap window | within its validity window |
| `retired` | no | no | within its validity window |
| `revoked` | no | no | no after the client refreshes the directory |

The active key is used for new proxy sessions. A deferred bundle contains a
notary-signed receipt, so `finalize` tries cached active and retiring records
and selects the endpoint whose key verifies that receipt. This lets a planned
rotation drain old bundles without making the notary store per-user state.

The authenticated provider-connection timestamp in a capture or finalized
package selects the key validity window. Local `verify` remains offline and
therefore uses the last cached directory. `publish` first verifies the package
locally, then refreshes the directory and enforces current revocation state
before sending any bytes.

Passing both `--trusted-notary-key` and an explicit `--notary` is an operator
override. It does not use directory lifecycle policy.

## Planned rotation

1. Start the replacement notary and keep the previous instance available.
2. Publish a directory that marks the replacement `active` and the previous
   key `retiring`. Give the old record a `valid_until_unix_ms` that covers the
   intended bundle-drain period.
3. New proxy sessions use the replacement. Existing bundles continue to route
   to the previous instance while it is `retiring`.
4. After the drain period, publish the old key as `retired` and stop its
   endpoint. Previously finalized evidence remains verifiable within the
   recorded window.

The API accepts the complete v2 document through
`LLM_NOTARY_NOTARY_DIRECTORY_JSON`. In the colocated Compose deployment, the
active record must match `LLM_NOTARY_NOTARY_PUBLIC_KEY`; the notary health
check independently confirms that this public key matches the mounted private
key. The existing single-key environment variables still generate a valid v2
directory, so no coordinated client flag day is required.

Clients also accept the v1 discovery document and migrate a v1 local trust
record on read.

## Emergency revocation

Publish the compromised key as `revoked` and designate a different active key.
Do not merely omit it: omission is interpreted as a planned retirement so
offline historical verification keeps working.

Revocation intentionally invalidates old evidence after directory refresh. A
compromised private key can create signatures with arbitrary old-looking
timestamps, so preserving those signatures as trustworthy would make the
revocation ineffective. Provider-native signatures or an external
transparency log would be required to distinguish pre-compromise evidence more
strongly.

## Deferred privacy-binding follow-up

Issue #36 may replace the current consent-based finalized package with a
privacy-preserving transcript-to-trace binding. That successor must carry the
notary key ID and authenticated connection timestamp, use this directory's
validity and revocation rules, and define migration behavior for already
published v2 directory records.
