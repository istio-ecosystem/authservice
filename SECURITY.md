# Security Policy

The Authservice maintainers and community take security seriously. We
appreciate your efforts to disclose your findings responsibly, and will make
every effort to acknowledge your contributions.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, pull requests, or any other public channel.**

Instead, please report vulnerabilities privately using the
[GitHub Security Advisory](https://github.com/istio-ecosystem/authservice/security/advisories/new)
("Report a vulnerability" on the repository's **Security** tab). This allows
the maintainers to triage the report and collaborate with you privately,
directly on GitHub.

If the vulnerability relates to Envoy Proxy or Istio (the components
that Authservice is built on top of) rather than Authservice itself,
please report it to the relevant upstream project:

- Envoy Proxy: https://github.com/envoyproxy/envoy/security/advisories/new
- Istio: https://github.com/istio/istio/security

### What to Include

To help us triage and resolve the issue as quickly as possible, please include
as much of the following information as you can:

- A description of the vulnerability and its potential impact.
- The affected version(s) of Authservice.
- Steps to reproduce the issue, including any sample configuration, requests, or
  proof-of-concept code.
- Any known workarounds or suggested remediation.

> [!Warning]
> If your report includes data that has privacy concerns, please
> sanitize the data before sharing it.

## Disclosure Process

After a vulnerability is reported, the maintainers will follow this process:

1. **Acknowledgement** — We will acknowledge receipt of your report.
2. **Triage** — We will investigate to validate the report, determine the
   affected versions, and assess the severity and impact.
3. **Fix and coordination** — We will work on a fix and coordinate a release
   timeline with you.
4. **Release and disclosure** — Once a fix is available, we will publish the
   patched release and an accompanying security advisory.

We will keep you informed throughout the process. If you would
like to be credited for the discovery, please let us know, and we will include
an acknowledgement in the advisory (with your consent).

Please keep the details of any reported vulnerability confidential until a fix
has been released and the embargo has been lifted, so that users have a chance
to upgrade.

## Security Updates

Security patches and advisories are announced through:

- The [GitHub Releases page](https://github.com/istio-ecosystem/authservice/releases)
- The [GitHub Security Advisories page](https://github.com/istio-ecosystem/authservice/security/advisories)

We recommend watching the repository and subscribing to these channels to stay
informed about security updates.

## Contact

If you have any general (non-sensitive) questions about this security policy,
please reach out to the maintainers listed in the [CODEOWNERS](CODEOWNERS) file.
To report a vulnerability, always use the private channel described
above — the [GitHub Security Advisory](https://github.com/istio-ecosystem/authservice/security/advisories/new)
— rather than a public channel.

Thank you for helping to keep Authservice and its users secure.
