
# Debugger

A place for quickly debugging common issues, we can add & improve these as more conditions are found. 

Currently supports:

- Check if an email can be sent from a given IP based on an SPF record.


## Run locally

Either with php directly:

`composer start`

or via docker (available at http://127.0.0.1:8083, set `PORT` in `.env` to change it):

`make up` (or `docker compose -p stapps-debugger up --build`)

Run the tests with `make test`.

## Deploy (Ba1 server)

Runs as a Docker container bound to `127.0.0.1:${PORT}`, behind the host reverse proxy for `debugger.stapps.io`. The code is mounted into the container and Composer installs on boot, so recreate the container after pulling.

```bash
cd /srv/debugger
git pull
docker compose -p stapps-debugger build --pull
docker compose -p stapps-debugger up -d --force-recreate
curl -I http://127.0.0.1:8083/
```
