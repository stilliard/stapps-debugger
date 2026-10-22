# Debugger

A place for quickly debugging common issues, we can add & improve these as more conditions are found. 

Currently supports:

- Check if an email can be sent from a given IP based on an SPF record.

It's a small Rust app: the whole server is [`src/main.rs`](src/main.rs), with the pages in [`templates/`](templates/). The SPF check uses the [mail-auth](https://crates.io/crates/mail-auth) library, looking up DNS through the system resolver.

Links can prefill the SPF form, e.g. `/spf?ip=1.2.3.4&email=info@example.com`. The check itself is a POST, so email addresses stay out of URLs and access logs.


## Run locally

With Docker (no Rust needed), available at http://127.0.0.1:8083 (set `PORT` in `.env` to change it):

`make up` (or `docker compose -p stapps-debugger up --build`)

Or with Rust installed (via [rustup](https://rustup.rs)):

`make serve` (`cargo run`)

Changes to `templates/` and `public/` need a rebuild/restart to show up, as they're built into the binary.

Run the tests with `make test` (`cargo test`), or `make test-dns` to also check real domains' SPF results, which needs internet access.

## Deploy (Ba1 server)

Runs as a Docker container bound to `127.0.0.1:${PORT}`, behind the host reverse proxy for `debugger.stapps.io`. The `Dockerfile` compiles the app and ships just the binary in an empty (`scratch`) image, so rebuild after pulling.

```bash
cd /srv/debugger
git pull
docker compose -p stapps-debugger build --pull
docker compose -p stapps-debugger up -d --force-recreate
curl -I http://127.0.0.1:8083/
```
