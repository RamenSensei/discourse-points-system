.PHONY: test build tidy run-pg stop-pg dev-init compose-up compose-down compose-logs

test:
	cd ledger/sidecar && go test -race -v ./...

build:
	cd ledger/sidecar && go build -o ../bin/ledger-sidecar ./cmd/ledger-sidecar
	cd ledger/sidecar && go build -o ../bin/ledger-admin   ./cmd/ledger-admin

tidy:
	cd ledger/sidecar && go mod tidy

run-pg:
	docker run -d --rm --name ledger-pg-dev \
		-e POSTGRES_USER=ledger -e POSTGRES_PASSWORD=ledger -e POSTGRES_DB=ledger \
		-p 127.0.0.1:5433:5432 postgres:16-alpine

stop-pg:
	docker stop ledger-pg-dev 2>/dev/null || true

# Quick "spin up PG → init genesis → smoke test API" pipeline
dev-init: build
	@if [ -z "$$ADMIN_PRIV_KEY_HEX" ] || [ -z "$$ADMIN_PUBKEY_HEX" ]; then \
		echo "Set ADMIN_PUBKEY_HEX and ADMIN_PRIV_KEY_HEX first (use bin/ledger-admin keygen)"; exit 1; \
	fi
	DATABASE_URL=postgres://ledger:ledger@127.0.0.1:5433/ledger?sslmode=disable \
	./bin/ledger-admin init --memo "dev genesis"

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

compose-logs:
	docker compose logs -f sidecar
