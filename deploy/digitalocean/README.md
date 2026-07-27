# DigitalOcean notary host

`cloud-init.yaml` provisions Docker and generates a fresh root-owned notary
signing key on the Droplet. It deliberately does not clone the repository:
Certified is private, and a long-lived server should pull an immutable image
from a private OCI registry instead.

For the one-off network experiment, the source was copied over SSH and built
on the Droplet. The verified path was:

```
local Certified proxy -> Droplet public TCP/7047 -> api.openai.com
```

Production deployment should have CI build and publish an image tagged by its
git SHA, then have the host pull that digest and run it with
`--restart unless-stopped`. Keep the private signing key on the host (or in a
managed secret store) and restrict TCP/7047 with the provider firewall until
the client-to-notary control protocol has authentication and rate limiting.
