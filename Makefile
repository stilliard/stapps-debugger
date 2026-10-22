-include .env
export

PROJECT=stapps-debugger

.PHONY: serve test test-dns up down

serve:
	PORT=$${PORT:-8083} cargo run

test:
	cargo test

# also checks real domains, so needs internet access
test-dns:
	cargo test -- --include-ignored

up:
	docker compose -p ${PROJECT} up --build

down:
	docker compose -p ${PROJECT} down
