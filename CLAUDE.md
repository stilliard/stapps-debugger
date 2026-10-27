# Debugger

A static site of debug tools (debugger.stapps.io) on Cloudflare Pages, with real users. See README.md for the full layout.

- Everything served is in `public/`: plain HTML, one stylesheet (`css/app.css`) and ES modules in `js/`. No build step or npm dependencies, so don't add a framework or bundler.
- The SPF check (`js/spf.js`) runs in the browser, looking up DNS over HTTPS with Cloudflare (`js/dns.js`), so emails aren't sent to us. Keep it that way.
- `public/_headers` sets a strict CSP (`default-src 'self'`): no inline scripts, styles or event handlers, and no third-party fonts or scripts unless the CSP is changed too.
- The SPF page's results are `<template>`s in `spf.html`, filled by `spf-page.js` (`data-field` / `data-if`). Template ids must not clash with element ids on the page.
- `/spf?ip=…&email=…` links prefill the form, and people rely on them, so keep those field names.
- Copy uses British spelling (e.g. "authorised").

## Commands

```bash
make serve     # http://localhost:8083, like Pages (clean URLs, _headers, 404.html)
make test      # unit tests, node --test
make test-dns  # also checks real domains, needs internet
```

## Checking the UI in a browser

Use `playwright-cli` (installed globally) against `make serve`. Run it from a scratch directory, as it writes `.playwright-cli/` logs and screenshots into the current directory.

```bash
playwright-cli open http://localhost:8083/
playwright-cli resize 1440 1000          # or 390 844 for phone width
playwright-cli goto "http://localhost:8083/spf?ip=192.0.2.1&email=info@github.com"
playwright-cli eval "() => document.querySelector('form').requestSubmit()"
playwright-cli screenshot --filename=spf.png   # --full-page for the whole page
```

Browser console errors are in `.playwright-cli/console-*.log`.
