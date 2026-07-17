DATABASE_URL ?= postgres://actiongate:actiongate@localhost:5432/actiongate?sslmode=disable

.PHONY: tidy test proto lint migrate river sqlc build

tidy:
	go mod tidy

# -p 4 bounds how many packages run at once: each integration package spins
# its own Postgres container, and unbounded parallelism exhausts Docker.
test:
	go test ./... -count=1 -p 4

build:
	go build ./...

proto:
	buf generate

lint:
	buf lint
	buf breaking --against '.git#branch=main,subdir=proto' || true

migrate:
	goose -dir migrations postgres "$(DATABASE_URL)" up

river:
	river migrate-up --database-url "$(DATABASE_URL)"

sqlc:
	sqlc generate
