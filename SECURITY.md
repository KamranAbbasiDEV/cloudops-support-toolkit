# Security and responsible use

- Run these checks only against applications and infrastructure you own or are authorized to troubleshoot.
- Never commit real access logs containing user identifiers, API tokens, cookies or personal data. The bundled sample data is synthetic.
- Do not put passwords, tokens or credentials in URLs. The URL health summary intentionally removes query strings and fragments.
- The URL check sends outbound requests. Avoid feeding it untrusted URLs inside a service with privileged network access.
- TLS validation uses the system trust store and hostname verification; failed validation is reported as critical.
- This project does not provision AWS resources or require AWS credentials.
- Send security reports privately to the repository maintainer rather than including exploit details in a public issue.
