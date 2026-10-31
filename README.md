# CloudOps Support Toolkit

**A lightweight Python toolkit for cloud-support triage:** HTTP checks, DNS resolution, TLS certificate expiry, Apache/Nginx access-log analysis and initial incident reporting.

Created as a hands-on **cloud support engineering portfolio project**. All bundled incident data and sample logs are **synthetic**, not real customer data.

## Features

| Capability | Description |
| --- | --- |
| HTTP availability | Response status and latency |
| DNS diagnostics | Resolved IP addresses and DNS failures |
| TLS checks | Certificate validation and expiry warnings |
| Access-log analysis | HTTP 4xx/5xx counts and top error endpoints |
| Incident reporting | Markdown triage and investigation notes |
| CI | Offline unit tests on Python 3.11, 3.12 and 3.13 |
| Docker | Container demo using non-root user |

**Scope:** Read-only, point-in-time diagnostics. Does not provision AWS infrastructure, guarantee uptime or confirm incident root causes.

## Quick start (Python 3.11+)

From the repository root:

```bash
python -m cloudops_toolkit analyze-logs samples/access.log
python -m cloudops_toolkit incident-report --health samples/demo-health.json --logs samples/access.log --output incident.md
```

The synthetic demo contains 10 log requests, including four 5xx and two 4xx responses, and a simulated unhealthy service.

## Check an authorized website

```bash
python -m cloudops_toolkit check https://example.com --timeout 5 --warn-days 30
python -m cloudops_toolkit check https://example.com --output health.json
```

Return codes: 0 = OK, 1 = warning, 2 = critical, 3 = command/file error. Avoid using untrusted URLs in privileged environments, especially because HTTP redirects can change hosts.

## Install as a command

```bash
python -m pip install -e .
cloudops --help
cloudops analyze-logs samples/access.log
```

On Windows PowerShell, use `py -3` instead of `python` if needed.

## Tests

```bash
python -m unittest discover -s tests -v
```

The ten tests run offline with mocked network operations. GitHub Actions runs the same checks on three Python versions.

## Docker

```bash
docker build -t cloudops-support-toolkit .
docker run --rm cloudops-support-toolkit
```

## Project layout

```text
cloudops_toolkit/
  checks.py       HTTP, DNS, TLS
  logs.py         Access log summaries
  reports.py      Incident report generation
  cli.py          CLI entrypoint
samples/          Synthetic demo inputs
tests/            Offline unit tests
docs/RUNBOOKS.md  Support investigation runbooks
.github/workflows/ci.yml
Dockerfile
pyproject.toml
```

## Example results

The synthetic access logs contain ten parsed requests, two 4xx errors and four 5xx errors. The busiest error path is `/api/orders`. Real-world log formats may require adapting the parser.

## Roadmap

- Scheduled uptime checks with alerts
- Optional AWS CloudWatch integration
- FastAPI-based operational dashboard
- Additional supported access-log formats

See [incident runbooks](docs/RUNBOOKS.md) and [security guidance](SECURITY.md).

MIT licensed. See [LICENSE](LICENSE).
