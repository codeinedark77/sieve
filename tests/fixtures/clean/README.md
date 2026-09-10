# billing-worker

Deploys from commit 4f8a1e9c2b6d0357af4e1c9d8b2a6f0e1d3c5b7a on merge to main.

Request tracing uses UUIDv4 correlation IDs, e.g. `f47ac10b-58cc-4372-a567-0e02b2c3d479`,
attached to every outbound log line.

## Local setup

```
cp .env.example .env
docker compose up -d
```

See CONTRIBUTING.md for the PR checklist.
