# Security policy

## Reporting a problem

Open a GitHub issue for documentation or defensive-code defects that do not contain sensitive data.

Do not attach:

- passwords or hashes
- access tokens
- LSASS dumps
- registry hive exports
- DPAPI material
- Kerberos tickets
- production screenshots containing secrets
- private hostnames, IP addresses, or tenant identifiers

For a suspected active compromise, follow your organization's incident-response process rather than publishing evidence in a public issue.

## Defensive boundary

The project intentionally excludes credential extraction and decryption functionality. Pull requests that add password dumping, LSASS dumping, memory scraping, vault decryption, or credential theft automation will not be accepted.
