# GitHub Actions Runner Controller

LLM Notary runs its Linux GitHub Actions jobs on repository-scoped, ephemeral
ARC runner scale sets in the `kevz-gpu` Kubernetes cluster. The runners execute
on the CPU worker node (`hexchess/node-class=cpu-worker`), never on the GPU.

- `llmnotary-ci` runs Rust and SPA checks without Docker.
- `llmnotary-docker` runs Compose validation, Buildx image builds, and the
  DigitalOcean deployment workflow. Its Docker-in-Docker sidecar is privileged,
  so keep it limited to one disposable runner.
- The release workflow intentionally remains on GitHub-hosted runners because
  it builds macOS and Windows artifacts.

## Install or update

These commands use the current pinned ARC chart version. Run them with the
`kevz-gpu` context.

```bash
helm upgrade --install arc \
  --namespace arc-system \
  --create-namespace \
  --version 0.14.2 \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller

helm upgrade --install llmnotary-ci \
  --namespace arc-llmnotary-ci \
  --create-namespace \
  --version 0.14.2 \
  -f deploy/arc/llmnotary-ci-values.yaml \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set

helm upgrade --install llmnotary-docker \
  --namespace arc-llmnotary-docker \
  --create-namespace \
  --version 0.14.2 \
  -f deploy/arc/llmnotary-docker-values.yaml \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set
```

Before installing either scale set, create a `llmnotary-github-auth` secret in
its namespace. Use a GitHub App where practical; never commit the credentials
or place them in a Helm values file. The secret must provide either ARC's
`github_token` key or the GitHub App keys described in the
[ARC documentation](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/deploy-runner-scale-sets).

Both scale sets have `minRunners: 0`, so only the controller and lightweight
listeners remain while jobs are idle. Inspect an active job with:

```bash
kubectl --context kevz-gpu get pods -n arc-llmnotary-ci -w
kubectl --context kevz-gpu get pods -n arc-llmnotary-docker -w
```
