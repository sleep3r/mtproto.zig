# Docker Monitoring Stack

This directory contains a minimal Docker Compose setup for running:

- `mtproto-zig`
- `Prometheus`
- `Grafana`

The stack is intended for a VPS or any other Linux host where you want:

- the proxy exposed on a public TCP port
- the metrics endpoint available only on localhost
- Prometheus scraping metrics from the proxy container
- Grafana available over SSH port forwarding

## Files

- [docker-compose.yml](/Users/freerunner/Work/misc/mtproto.zig/hack/docker/docker-compose.yml)
- [prometheus.yml](/Users/freerunner/Work/misc/mtproto.zig/hack/docker/prometheus.yml)
- [mtproto-zig-grafana.json](/Users/freerunner/Work/misc/mtproto.zig/hack/docker/mtproto-zig-grafana.json)

## 1. Prepare the proxy config

Create `zigconf.toml` next to [docker-compose.yml](/Users/freerunner/Work/misc/mtproto.zig/hack/docker/docker-compose.yml).

The important part for metrics is:

```toml
[monitoring]
enabled = true
host = "0.0.0.0"
port = 9100
```

`host = "0.0.0.0"` is required because Prometheus connects to the proxy from another container over the Docker network.

## 2. Set the proxy image tag

Edit [docker-compose.yml](/Users/freerunner/Work/misc/mtproto.zig/hack/docker/docker-compose.yml) and replace:

```yaml
mtproto-zig:<change_me>
```

with the image tag you actually want to run.

## 3. Start the stack

From `hack/docker` run:

```bash
docker compose up -d
```

This starts:

- `mtg-zig` on `10000:8443`
- Prometheus on `127.0.0.1:9090`
- Grafana on `127.0.0.1:3000`

Make sure that you have proper port in server.port configured. 443 is the default, but in that example we use 8443 as 
internal port inside container and 10000 as exposed port on the host.

## 4. Check that metrics are available

On the VM:

```bash
curl -s http://127.0.0.1:9100/metrics | head
```

Prometheus target check:

```bash
curl -s http://127.0.0.1:9090/api/v1/targets | jq .
```

You should see `mtg-zig:9100` in the target list with `health: "up"`.

## 5. Open Grafana over SSH

From your local machine:

```bash
ssh -L 3000:127.0.0.1:3000 <vm_ssh_user>@<vm_ip>
```

Then open:

```text
http://127.0.0.1:3000
```

Default login from [docker-compose.yml](/Users/freerunner/Work/misc/mtproto.zig/hack/docker/docker-compose.yml):

- username: `admin`
- password: `admin`

## 6. Add the Prometheus datasource in Grafana

In Grafana:

1. Open `Connections` -> `Data sources`
2. Click `Add data source`
3. Choose `Prometheus`
4. Set the URL to:

```text
http://prometheus:9090
```

5. Click `Save & test`

This works because Grafana and Prometheus run in the same Compose network.

## 7. Import the dashboard

In Grafana:

1. Open `Dashboards` -> `New` -> `Import`
2. Upload [mtproto-zig-grafana.json](/Users/freerunner/Work/misc/mtproto.zig/hack/docker/mtproto-zig-grafana.json)
3. Select your Prometheus datasource
4. Click `Import`

The dashboard includes:

- active connections
- memory usage
- total throughput
- total transferred bytes
- traffic throughput graphs
- per-user active connections
- top users by throughput
- top users by transferred bytes

## Notes

- The proxy metrics are exposed on `127.0.0.1:9100` on the host, not publicly.
- Per-user metrics are generated from users in the proxy config loaded by the current process.
- Counter-based totals reset on proxy restart, which is expected for Prometheus counters.
