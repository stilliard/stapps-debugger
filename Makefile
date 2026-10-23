-include .env
export

PROJECT=stapps-debugger
PORT ?= 8083

.PHONY: serve test test-dns docker-up

serve:
	cargo run

test:
	cargo test

# also checks real domains, so needs internet access
test-dns:
	cargo test -- --include-ignored

docker-up:
	docker build -t $(PROJECT) .
	docker run --rm -p 127.0.0.1:$(PORT):8080 $(PROJECT)
