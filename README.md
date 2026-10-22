# Debugger

A place for quickly debugging common issues, we can add & improve these as more conditions are found. 

Currently supports:

- Check if an email can be sent from a given IP based on an SPF record.

It's a small Rust app, split up much like the PHP version was:

- [`src/main.rs`](src/main.rs) starts the server
- [`src/routes.rs`](src/routes.rs) has the URLs and what each one does
- [`src/spf.rs`](src/spf.rs) checks SPF records, using the [mail-auth](https://crates.io/crates/mail-auth) library and the system's DNS resolver
- [`src/pages.rs`](src/pages.rs) renders the pages from the templates in [`templates/`](templates/)
- [`src/security_headers.rs`](src/security_headers.rs) adds security headers to every response

Links can prefill the SPF form, e.g. `/spf?ip=1.2.3.4&email=info@example.com`. The check itself is a POST, so email addresses stay out of URLs and access logs.


## Run locally

With Docker (no Rust needed):
```bash
cp .env.example .env  # optionally adjust PORT
make docker-up        # build and run, Ctrl+C to stop
```

Or with Rust installed (via [rustup](https://rustup.rs)):
```bash
make serve     # cargo run
make test      # cargo test
make test-dns  # also checks real domains' SPF results, so needs internet access
```

The app runs on `http://localhost:8083` by default. Set `PORT` in `.env` to use a different port. Changes to `templates/` and `public/` need a rebuild/restart to show up, as they're built into the binary.

## Deploy (Dokku on Ba1)

Dokku builds the `Dockerfile`, which compiles the app and ships just the binary in an empty (`scratch`) image.

```bash
git remote add dokku dokku@<ba1-host>:debugger  # first time only
git push dokku master:main
curl -I https://debugger.stapps.io/
```

The app listens on `$PORT` (8080 in the image). Dokku would serve that on port 8080 too, so the app was set up with:

```bash
dokku apps:create debugger
dokku domains:set debugger debugger.stapps.io
dokku ports:set debugger http:80:8080 https:443:8080
tar cf - server.crt server.key | ssh dokku@<ba1-host> certs:add debugger  # the stapps.io Cloudflare origin cert
```
