-include .env
export

PORT ?= 8083

.PHONY: serve test test-dns

# serves public/ like Cloudflare Pages does, e.g. /spf for spf.html, with _headers and 404.html
serve:
	npx wrangler@4 pages dev public --port $(PORT)

test:
	node --test tests/spf.test.js

# also checks real domains, so needs internet access
test-dns:
	node --test tests/*.test.js
