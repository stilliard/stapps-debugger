.PHONY: up down shell test

PROJECT=stapps-debugger

up:
	docker compose -p ${PROJECT} up --build

down:
	docker compose -p ${PROJECT} down

shell:
	docker compose -p ${PROJECT} run --rm app bash

test:
	# one container, as each `run` boots the entrypoint's `composer install --no-dev`, which removes phpunit again
	docker compose -p ${PROJECT} run --rm app sh -c "composer install --no-interaction --no-progress && vendor/bin/phpunit"
