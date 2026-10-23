# Debugger

A place for quickly debugging common issues, we can add & improve these as more conditions are found. 

Currently supports:

- Check if an email can be sent from a given IP based on an SPF record.

It's a static site on Cloudflare Pages, with no server. The SPF checks run in the visitor's browser, looking up DNS with [Cloudflare's DNS over HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/), so email addresses aren't sent to us, and there's nothing for bots to abuse.

The DNS lookups are the same ones a mail server makes when checking SPF, so Cloudflare's DNS (and the DNS servers for the domains in the record) see the email's domain. The few records that use the `%{l}` or `%{s}` macros put the part before the `@` in a lookup too.

Everything Pages serves is in [`public/`](public/):

- [`index.html`](public/index.html), [`spf.html`](public/spf.html) and [`404.html`](public/404.html) are the pages, styled by [`css/app.css`](public/css/app.css)
- [`js/spf-page.js`](public/js/spf-page.js) runs the SPF page's form and shows the results
- [`js/spf.js`](public/js/spf.js) checks SPF records, following [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) for everything real records use, but skipping some of its stricter checks on broken records
- [`js/dns.js`](public/js/dns.js) does the DNS lookups
- [`_headers`](public/_headers) adds security headers to every response

Links can prefill the SPF form, e.g. `/spf?ip=1.2.3.4&email=info@example.com`. There's no build step or npm dependencies; the JavaScript is served as it is.


## Run locally

With [Node](https://nodejs.org) 22+ installed:
```bash
make serve     # serves public/ like Pages does, using Cloudflare's wrangler
make test      # node --test
make test-dns  # also checks real domains' SPF results, so needs internet access
```

The site runs on `http://localhost:8083` by default. Set `PORT` in `.env` to use a different port (see `.env.example`).

## Deploy (Cloudflare Pages)

Pages deploys from GitHub on every push: `master` goes live, and other branches get preview URLs.

It's set up in the Cloudflare dashboard (Workers & Pages → Create → Pages → Connect to Git) with:

- Production branch: `master`
- Build command: none
- Build output directory: `public`
- Custom domain: `debugger.stapps.io`
