# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| Latest on `main` | Yes |
| Older commits | No |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Please report via **GitHub Security Advisories** on this repository:

1. Open the repo **Security** tab  
2. **Report a vulnerability**  
3. Include impact, reproduction steps, and affected versions if known  

If Advisories are unavailable, contact the repository owner privately (GitHub profile / email listed there).

We will acknowledge reports as soon as practical and coordinate a fix before any public disclosure.

## What not to report as “secrets in this repo”

This project is designed so that:

- AccessKey **Secret** never lives in the Worker  
- AccessKey **Id** is a Cloudflare **secret**, not source  
- Bucket names and private endpoints belong only in **local** `wrangler.toml.local` (gitignored)

If you find a real AccessKey, signing secret, or private credential in a commit, treat it as a vulnerability and report it as above.
