# Integration Tests

These tests validate vulnerability checks against two dockerized TLS endpoints:

- `nginx_good` on `127.0.0.1:443` (expected safe for CCS injection)
- `nginx_bad` on `127.0.0.1:8443` (expected vulnerable for CCS injection)

## Run

From repository root:

```bash
make integration-up
make test-integration
make integration-down
```

Or directly from `integration_tests/`:

```bash
docker compose up -d
go test -v -tags=integration ./...
docker compose down
```

## Environment Overrides

You can override host/port defaults:

- `NGINX_GOOD_HOST`, `NGINX_GOOD_PORT`
- `NGINX_BAD_HOST`, `NGINX_BAD_PORT`
- `NGINX_GOOD_EXPECTED_CCS` (default: `no`)
- `NGINX_BAD_EXPECTED_CCS` (default: `no`)
