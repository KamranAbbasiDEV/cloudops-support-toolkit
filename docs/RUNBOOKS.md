# Incident runbooks

Starting points for technical support triage. Follow your organization's incident response policy.

## HTTP 5xx spike

1. Identify affected endpoints and time window from access logs.
2. Compare 5xx rate with baseline and recent deployments.
3. Check application logs, reverse-proxy upstream errors, dependency health and resource saturation.
4. Reproduce in a controlled manner and establish customer impact.
5. Escalate with timeline, routes, error codes, monitoring evidence and checks performed.
6. After recovery, verify performance and document the root cause only when confirmed.

## TLS certificate warning

1. Verify presented certificate, hostname and chain.
2. Identify issuing CA and renewal owner.
3. Follow approved renewal procedures; do not put private keys in tickets.
4. Verify expiry from an external client.
5. Update the runbook and renewal alerts.

## DNS lookup failure

1. Check whether the failure is resolver-specific.
2. Verify nameservers, A/AAAA/CNAME records and TTLs.
3. Check recent changes and delegation.
4. Compare authoritative and recursive answers.
5. Record before/after findings and notify stakeholders.

## Escalation packet template

- Incident start time and timezone:
- Application/customer impact:
- Affected hosts and paths (redact private data):
- Expected vs actual behavior:
- Error evidence and timestamps:
- Checks completed:
- Owner:
- Next update:
