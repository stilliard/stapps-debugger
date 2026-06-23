.PHONY: up down shell test

PROJECT=stapps-debugger

up:
	docker compose -p ${PROJECT} up

down:
	docker compose -p ${PROJECT} down

shell:
	docker compose -p ${PROJECT} run --rm app bash

test:
	docker compose -p ${PROJECT} run --rm app composer install --no-interaction --no-progress && \
	docker compose -p ${PROJECT} run --rm app vendor/bin/phpunit
