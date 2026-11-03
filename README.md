# OpenHunter

OpenHunter is a free, self-hosted alternative to Hunter.io for a job seeker doing targeted outreach. It discovers people and public email addresses at a company, infers the mailbox pattern, ranks likely addresses for one person, and checks an address without sending mail. The same operations are available as a command-line tool and as an MCP stdio server.

No paid API is required. An optional `GITHUB_TOKEN` raises the GitHub rate limit. Every address OpenHunter returns came from a public page or the public GitHub API. It does not log in, and it does not send email.

## Install

Requires Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

The database defaults to `~/.local/share/openhunter/openhunter.db`. Override it with `OPENHUNTER_DB`.

## CLI

```bash
openhunter domain-search runpod.io
openhunter domain-search "Runpod"          # resolves the site from the GitHub org profile
openhunter pattern runpod.io
openhunter find --first Donovan --last Clarke --domain runpod.io
openhunter verify dan.stotts@runpod.io
openhunter leads save --email help@runpod.io --name Runpod --domain runpod.io --role organization
openhunter leads list --domain runpod.io
openhunter leads export leads.csv --domain runpod.io
```

Add `--json` for the raw result and `--refresh` to ignore the cache. `openhunter mcp` starts the stdio server (the installed console script `openhunter-mcp` does the same).

## MCP

The server speaks MCP over stdio and exposes `domain_search`, `email_pattern`, `email_finder`, `email_verifier`, `save_lead`, `list_leads`, and `export_leads`.

Cursor (`.cursor/mcp.json`) or Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openhunter": {
      "command": "/absolute/path/to/.venv/bin/openhunter-mcp",
      "env": {
        "GITHUB_TOKEN": "",
        "OPENHUNTER_DB": "/absolute/path/to/openhunter.db"
      }
    }
  }
}
```

Leave `GITHUB_TOKEN` empty to use the unauthenticated API. Any MCP client that can launch a stdio process can use the same command.

## Demo against runpod.io

Captured on 3 November 2026 from a network where outbound port 25 is blocked. The company website did not publish individual mailboxes. The addresses below are already public in GitHub commit metadata and on the `runpod` organization profile. Public GitHub profiles for these accounts did not include a name, so pattern inference stayed a structural guess.

```text
$ openhunter domain-search runpod.io --refresh
runpod.io  Runpod  (live)
pattern: first.last  confidence 0.34  (structural, 6/6)
  Runpod  organization  help@runpod.io  0.8  github_org  https://github.com/runpod
  danstotts-ops  -  dan.stotts@runpod.io  0.75  github_commit  https://github.com/runpod/docs/commit/02379524f1d057200d839d013114f2e8817eaa85
  daveseddon-runpod  -  dave.seddon@runpod.io  0.75  github_commit  https://github.com/runpod/rplog/commit/651b581040df198fbf48f97fec843d828384bd54
  erinavllazagaj-eng  -  erin.avllazagaj@runpod.io  0.75  github_commit  https://github.com/runpod/runpod-python/commit/714a565514bae7dd2b6ca355b52e8e76d70d1102
  galen-runpod  -  galen.osullivan@runpod.io  0.75  github_commit  https://github.com/runpod/rplog/commit/5a3653d31956f84b9b4fdd45e8b5a26ae64c332f
  lgunreddi  -  lavanya.gunreddi@runpod.io  0.75  github_commit  https://github.com/runpod/docs/commit/90c4635e0f0d363d89a014b7771c362facc9d23e
  marie-karpinska  -  marie.karpinska@runpod.io  0.75  github_commit  https://github.com/runpod/runpod-python/commit/2217b6d15a0554e2652506068f438d740392ad37
  Dean Quiñanola  -  -  0.7  github_member  https://github.com/deanq
  Donovan Clarke  -  -  0.7  github_member  https://github.com/donovanclarke

$ openhunter pattern runpod.io
runpod.io: first.last  confidence 0.34  method structural
note: Structural guess only: local parts look like first.last and no names were available to confirm it.
```

`email_finder` ranks candidates. It does not confirm that the mailbox exists. Donovan Clarke is a public org member with no published address, so every line below is a guess:

```text
$ openhunter find --first Donovan --last Clarke --domain runpod.io
1. donovan.clarke@runpod.io  first.last  score 0.59  matches inferred pattern first.last
2. dclarke@runpod.io  flast  score 0.18  common corporate pattern
3. donovan@runpod.io  first  score 0.1  common corporate pattern
4. donovanclarke@runpod.io  firstlast  score 0.08  common corporate pattern
5. d.clarke@runpod.io  f.last  score 0.05  common corporate pattern
6. donovan_clarke@runpod.io  first_last  score 0.03  common corporate pattern
7. donovanc@runpod.io  firstl  score 0.02  common corporate pattern
8. clarke.donovan@runpod.io  last.first  score 0.01  common corporate pattern
```

Verification of a public commit address reached Google's MX records and then stopped. Nothing was sent:

```json
{
  "email": "dan.stotts@runpod.io",
  "status": "unknown",
  "score": 40,
  "syntax_ok": true,
  "is_disposable": false,
  "is_role": false,
  "mx_hosts": [
    "aspmx.l.google.com",
    "alt1.aspmx.l.google.com",
    "alt2.aspmx.l.google.com",
    "alt3.aspmx.l.google.com",
    "alt4.aspmx.l.google.com"
  ],
  "smtp_code": null,
  "smtp_error": "blocked",
  "catch_all": null,
  "notes": ["Outbound port 25 was unreachable or timed out; the mailbox was not verified."]
}
```

`help@runpod.io` is reported as a role address with the same `unknown` SMTP result. `not an email` is `invalid` with score 0 before any network call. `someone@mailinator.com` is flagged disposable.

When a public GitHub profile does publish "First Last", that name is attached to the commit address and can vote in pattern inference. The commit URL stays the source of the address.

## Confidence

Named pattern confidence is `ratio * (1 - 0.55 ** n)`, capped at 0.97. One agreeing named address is 0.45. Three are about 0.83. A structural guess with no names requires at least three addresses and 75% agreement, and it is capped at 0.34 so it cannot outrank a single named match. Role inboxes (`info@`, `help@`, `security@`) are not pattern evidence.

Verifier status is one of `valid`, `invalid`, `accept_all`, or `unknown`. `accept_all` means the server also accepted a random nonexistent mailbox, so a positive `RCPT` does not prove the person exists. `unknown` means the probe could not finish, usually because port 25 was blocked or the server gave a temporary answer.

## Limits

- **Port 25.** Many networks, including this demo environment and most cloud hosts, block outbound SMTP. OpenHunter reports `unknown` and does not pretend the mailbox was confirmed. Set `OPENHUNTER_SMTP=0` to skip the probe and keep the syntax, MX, disposable, and role checks.
- **Catch-all domains.** A domain that accepts every recipient cannot be used to prove an address. Status is `accept_all` and the score stays modest.
- **GitHub quota and terms.** Unauthenticated requests are 60 per hour per IP. A token (`GITHUB_TOKEN` or `GH_TOKEN`) raises that to 5,000. One domain search looks at the org, public members, up to 5 recently pushed public repos, 15 commits each, and up to 12 profiles. Noreply addresses and bot authors are dropped. Use the official REST API only, and follow GitHub's terms.
- **Polite crawling.** The website walk requests `robots.txt` and skips disallowed paths. It fetches at most 12 same-site pages (home, about, team, contact, careers, `security.txt`, `humans.txt`, plus team links found on the home page), with a short delay between requests. It does not cross into a login wall.
- **Public data only.** A missing email means nothing was published, not that the person has no mailbox. Do not treat a candidate from `email_finder` as a verified address.
- **Cache.** Domain searches are cached for 7 days and verifications for 24 hours. `--refresh` bypasses that.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` or `GH_TOKEN` | unset | GitHub API authentication |
| `OPENHUNTER_DB` | `~/.local/share/openhunter/openhunter.db` | SQLite cache and leads |
| `OPENHUNTER_SMTP` | on | Set to `0` to skip the RCPT probe |
| `OPENHUNTER_SMTP_TIMEOUT` | `5` | Seconds for DNS and SMTP |
| `OPENHUNTER_DISPOSABLE_FILE` | unset | Extra disposable domains, one per line |
| `OPENHUNTER_LOG` | `WARNING` | Log level |

## Tests

```bash
pytest
```

The suite covers pattern inference, SMTP interpretation (including a blocked port 25), DNS and null-MX handling, HTML extraction, the GitHub and website walkers, the SQLite cache and lead export, the CLI, and both the in-process and stdio MCP servers.
