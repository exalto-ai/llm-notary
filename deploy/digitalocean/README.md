# DigitalOcean deployment

One Droplet runs both public services through Docker Compose:

```text
internet ── HTTPS ──> web (Caddy + SPA)       ports 80/443
local proxies ──────> notary                  port 7047
```

The website and the raw TCP notary are deliberately separate entry points.
The named Cloudflare Tunnel exposes only the website; the local proxy continues
to connect directly to the Droplet’s IP on TCP 7047.

## First-time Droplet setup

Create an Ubuntu Droplet with `cloud-init.yaml`. It installs Docker and the
Compose plugin, creates `/opt/llm-notary`, and generates a root-owned signing
key at `/opt/llm-notary/notary-signing-key`.

Configure a DigitalOcean Cloud Firewall:

- TCP `80` and `443` from anywhere for the website.
- TCP `7047` only from approved beta-tester IPs until the notary protocol has
  authentication and rate limiting.
- TCP `22` only from deployment/admin IPs.

Point `SITE_DOMAIN` at the Droplet before deploying. Caddy obtains and renews
the TLS certificate automatically once DNS resolves.

Configure these GitHub repository secrets before the first deployment:

- `DO_SSH_HOST`, `DO_SSH_USER`, and `DO_SSH_PRIVATE_KEY` for the Droplet.
- `DO_SSH_PORT` only when SSH is not on port 22.
- `SITE_DOMAIN` for the website’s DNS name.
- `CLOUDFLARE_TUNNEL_TOKEN` for the remotely managed Cloudflare Tunnel.

The generated notary signing key intentionally stays on the Droplet. Do not
add it to a GitHub secret, image, or `.env` file.

## Deploying with TTL.sh

The GitHub Actions deployment workflow pushes unique, public, 24-hour image
tags to TTL.sh, uploads `compose.yml`, and runs Compose on the Droplet. The
notary key is never pushed to TTL.sh or GitHub: Compose mounts the key from the
host as a Docker secret.

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
network, exactly where `cloudflared` runs. Saving the route creates the tunnel
DNS record automatically when `exalto.ai` is managed by Cloudflare. Public TLS
terminates at Cloudflare; the tunnel-to-web hop stays private HTTP.
