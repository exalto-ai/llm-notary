# DigitalOcean deployment

One Droplet runs both public services through Docker Compose:

```text
internet ── HTTPS ──> Cloudflare Tunnel ──> web (stable Caddy gateway)
                                                    ├──> site (SPA)
                                                    └──> api (GitHub OAuth + SQLite)
local proxies ──────> notary                  port 7047
```

The website and the raw TCP notary are deliberately separate entry points.
The named Cloudflare Tunnel exposes only the website; the local proxy continues
to connect directly to the Droplet’s IP on TCP 7047.

The API publishes that TCP endpoint and matching public signing key to released
clients at `/api/notary`. The deploy workflow derives the public key from the
host-only signing key and Compose checks that it matches the running notary.
The deployment workflow uses `DO_SSH_HOST` as `LLM_NOTARY_NOTARY_HOST`, so the
Droplet's reserved IP is configured on the server rather than embedded in the
CLI. If the notary later moves to another machine, set that variable explicitly
in `deploy.env` and update the workflow accordingly.

## First-time Droplet setup

Create an Ubuntu Droplet with `cloud-init.yaml`. It installs Docker and the
Compose plugin, creates `/opt/llm-notary`, and generates a root-owned signing
key at `/opt/llm-notary/notary-signing-key`.

Configure a DigitalOcean Cloud Firewall:

- TCP `7047` only from approved beta-tester IPs until the notary protocol has
  authentication and rate limiting.
- TCP `22` only from deployment/admin IPs.

The named Cloudflare Tunnel carries all website traffic, so the Droplet does
not need public `80` or `443`. Public TLS terminates at Cloudflare.

Configure these GitHub repository secrets before the first deployment:

- `DO_SSH_HOST`, `DO_SSH_USER`, and `DO_SSH_PRIVATE_KEY` for the Droplet.
- `DO_SSH_PORT` only when SSH is not on port 22.
- `SITE_DOMAIN` for the website’s DNS name.
- `CLOUDFLARE_TUNNEL_TOKEN` for the remotely managed Cloudflare Tunnel.
- `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` for the LLM
  Notary GitHub OAuth App. The app's callback URL must be
  `https://llmnotary.exalto.ai/api/auth/github/callback`.
- `LLM_NOTARY_SPACES_ACCESS_KEY_ID` and
  `LLM_NOTARY_SPACES_SECRET_ACCESS_KEY` for a key restricted to read/write
  access on the private intake Space.

Configure these repository variables alongside the secrets:

- `LLM_NOTARY_SPACES_BUCKET` is the private Standard Storage bucket name.
- `LLM_NOTARY_SPACES_ENDPOINT` is the regional origin endpoint, such as
  `https://sfo3.digitaloceanspaces.com`.
- `LLM_NOTARY_SPACES_REGION` is the matching region, such as `sfo3`.

For this deployment, add those two values as GitHub Actions secrets named
`LLM_NOTARY_GITHUB_OAUTH_CLIENT_ID` and
`LLM_NOTARY_GITHUB_OAUTH_CLIENT_SECRET`. They are written only to the
Droplet's root-owned `deploy.env` at deploy time and are not included in either
image.

The generated notary signing key intentionally stays on the Droplet. Do not
add it to a GitHub secret, image, or `.env` file.

The API stores its initial user and session records in the Docker volume
`api_data`. It is intentionally a single-instance SQLite deployment while the
product is in beta; move it to managed Postgres before horizontally scaling the
API or running background publication workers.

## Private publication intake

The API creates a short-lived presigned PUT for a staging object under
`llm-notary/uploads/`. After the authenticated client completes the job, the
API copies the object to a server-only key under `llm-notary/intake/`, verifies
the copied object's size and signed metadata, queues the job, and removes the
staging object. The admission worker added later consumes only the server-only
key and computes the actual SHA-256 before trusting the package.

The Space must remain private and must not have a CDN. Use a bucket-scoped
`readwrite` Spaces key in production. Configure lifecycle rules as a recovery
backstop:

- expire `llm-notary/uploads/` after one day;
- expire `llm-notary/intake/` after seven days.

Application cleanup removes ordinary expired staging uploads after 15 minutes.
The lifecycle rules cover process downtime and orphaned objects; the later
admission worker is still responsible for prompt deletion after admission or
rejection.

## Deploying with TTL.sh

The GitHub Actions deployment workflow pushes unique, public, 24-hour image
tags to TTL.sh, uploads the Compose and gateway configuration, and runs Compose
on the Droplet. The tunnel always connects to the stable `web` gateway; the
replaceable SPA and API containers sit behind it. The gateway retries briefly
while those services start, avoiding the Cloudflare 502s caused by replacing the
tunnel's origin directly. The notary key is never pushed to TTL.sh or GitHub:
Compose mounts the key from the host as a Docker secret.

TTL.sh is appropriate for this shared MVP environment, but it is not a durable
registry. The Droplet keeps already-pulled images running, but host recovery or
rollback after 24 hours requires a fresh deployment. When the service needs a
durable release history, switch `NOTARY_IMAGE` and `WEB_IMAGE` to GHCR or the
DigitalOcean Container Registry; the Compose file does not need to change.

## Manual local or Droplet run

Copy `deploy.env.example` to `deploy.env`, set image references and the host
key path, then run:

```bash
docker compose --env-file deploy/digitalocean/deploy.env pull
docker compose --env-file deploy/digitalocean/deploy.env up -d
```

## Cloudflare hostname

In the Cloudflare dashboard, open **Networking → Tunnels**, select this named
tunnel, then under **Routes** add a **Published application**:

- **Hostname:** `llmnotary.exalto.ai`
- **Service type:** HTTP
- **Service URL:** `http://web:80`

`web` is the Compose service name, so it resolves only inside the Compose
network, exactly where `cloudflared` runs. It is a stable gateway, so this
Cloudflare route does not change when the SPA or API is deployed. Saving the
route creates the tunnel DNS record automatically when `exalto.ai` is managed
by Cloudflare. Public TLS terminates at Cloudflare; the tunnel-to-web hop stays
private HTTP.
