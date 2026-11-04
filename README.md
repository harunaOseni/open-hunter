# OpenHunter

OpenHunter is a free, self-hosted alternative to Hunter.io for a job seeker doing targeted outreach. It discovers people and public email addresses at a company, infers the mailbox pattern, ranks likely addresses for one person, and checks an address without sending mail. The same operations are available as a command-line tool and as an MCP stdio server.

No paid API is required. An optional `GITHUB_TOKEN` raises the GitHub rate limit. Addresses come from public pages, public web search, and the public GitHub API. OpenHunter does not log in, and it does not send email. Every address it keeps is stored in a local index with the page it came from and the first and last time it was seen, so later lookups reuse what was already found.

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

Captured on 3 November 2026 with no `GITHUB_TOKEN`. `runpod.io` resolves to the `runpod` GitHub organization, and a bare company name does the same: `openhunter domain-search Runpod` reads the org profile and continues as a search for `runpod.io`. The company site's own pages did not publish personal mailboxes. GitHub commit metadata and one public press article did. Those GitHub profiles do not publish real names, so the pattern stays a structural guess. `seen` is the first day the address was stored in the local index.

```text
$ openhunter domain-search runpod.io --refresh
runpod.io  Runpod  (live)
pattern: first.last  confidence 0.34  (structural, 6/7)
  Runpod  organization  help@runpod.io  0.8  github_org  https://github.com/runpod  seen 2026-11-03
  danstotts-ops  -  dan.stotts@runpod.io  0.75  github_commit  https://github.com/runpod/docs/commit/02379524f1d057200d839d013114f2e8817eaa85  seen 2026-11-03
  daveseddon-runpod  -  dave.seddon@runpod.io  0.75  github_commit  https://github.com/runpod/rplog/commit/651b581040df198fbf48f97fec843d828384bd54  seen 2026-11-03
  erinavllazagaj-eng  -  erin.avllazagaj@runpod.io  0.75  github_commit  https://github.com/runpod/runpod-python/commit/714a565514bae7dd2b6ca355b52e8e76d70d1102  seen 2026-11-03
  galen-runpod  -  galen.osullivan@runpod.io  0.75  github_commit  https://github.com/runpod/rplog/commit/5a3653d31956f84b9b4fdd45e8b5a26ae64c332f  seen 2026-11-03
  lgunreddi  -  lavanya.gunreddi@runpod.io  0.75  github_commit  https://github.com/runpod/docs/commit/90c4635e0f0d363d89a014b7771c362facc9d23e  seen 2026-11-03
  marie-karpinska  -  marie.karpinska@runpod.io  0.75  github_commit  https://github.com/runpod/runpod-python/commit/2217b6d15a0554e2652506068f438d740392ad37  seen 2026-11-03
  Dean Quiñanola  -  -  0.7  github_member  https://github.com/deanq
  Donovan Clarke  -  -  0.7  github_member  https://github.com/donovanclarke
  -  -  more@runpod.io  0.6  web_search  https://aijourn.com/runpod-raises-100m-led-by-summit-partners-to-accelerate-the-ai-developer-cloud/  seen 2026-11-03
note: Read a sitemap with 40 locations.
note: Searched DuckDuckGo for @runpod.io, "runpod.io" email, and talk/press mentions. Fetched 1 page.
note: DuckDuckGo search for '"runpod.io" email' failed (HTTP 202).
note: Skipped search result https://www.instagram.com/runpod.io/: robots.txt disallows it.
note: Skipped search result https://www.linkedin.com/company/runpod-io/: robots.txt disallows it.
note: Skipped search result https://x.com/runpod: robots.txt disallows it.
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

A sandbox resolver that answers MX with `NoAnswer` and then an A record in `198.18.0.0/15` is not treated as a mail host. With `OPENHUNTER_DNS_MODE=auto` (the default) the lookup is repeated over DNS-over-HTTPS, Cloudflare then Google, and the real exchanges are used (for a Google Workspace domain those are `aspmx.l.google.com` and the `alt` hosts). If one of those servers accepts TCP and never sends an SMTP greeting, the result is `status` `unknown`, `reason` `smtp_unreachable`, and `mx_valid` true. `valid` is returned only after a real `RCPT` accept and a rejecting probe of a nonexistent mailbox. Nothing is sent.

When a public GitHub profile does publish "First Last", that name is attached to the commit address and can vote in pattern inference. The commit URL stays the source of the address.

## Sources and the local index

Each `domain_search` does four things, then merges them:

- **Company site.** `robots.txt` is read first. The crawl then takes `sitemap.xml` (including one level of sitemap indexes), home, about, team, contact, blog, press, newsroom, and careers pages, plus up to 3 same-site PDFs. The budget is 12 HTML responses and those 3 PDFs. If `https://example.com/` cannot be fetched, `https://www.example.com/` is tried. A redirect off the company host is skipped and noted.
- **Web search.** Queries are `@{domain}`, `"domain" email`, and a talk/press query. The default backend is the DuckDuckGo HTML endpoint, which needs no key. Set `SEARXNG_URL` or `BRAVE_SEARCH_API_KEY` to use that backend instead; DuckDuckGo is the fallback when the configured one cannot be reached. At most 6 result pages are fetched. `robots.txt` on those hosts is honored. Pages behind a login are not requested.
- **GitHub.** The organization slug is the domain stem (`runpod.io` → `runpod`), tried before any other hint so links to unrelated accounts cannot crowd it out. A company name that is not a domain is resolved from the org profile's website or email, and if `/orgs/{name}` is missing, from GitHub's organization search. Public member profiles and commit authors on up to 5 repos are included. Noreply and bot addresses are dropped.
- **Local index.** Every on-domain address is written to SQLite with its source URL, confidence, and `first_seen` / `last_seen`. The next search for that domain returns those rows even when a source is quiet, and pattern inference sees them too. A lookup that found nothing because a source could not be reached is not cached.

When nothing is found, the notes list the GitHub URLs that were tried and the HTTP status or transport error, instead of only saying that no organization exists.

## Confidence

Named pattern confidence is `ratio * (1 - 0.55 ** n)`, capped at 0.97. One agreeing named address is 0.45. Three are about 0.83. A structural guess with no names requires at least three addresses and 75% agreement, and it is capped at 0.34 so it cannot outrank a single named match. Role inboxes (`info@`, `help@`, `security@`) are not pattern evidence.

Verifier status is one of `valid`, `invalid`, `accept_all`, or `unknown`. `valid` means the server accepted `RCPT` for the address and rejected `RCPT` for a random nonexistent mailbox. `accept_all` means the server also accepted that random mailbox, so a positive `RCPT` does not prove the person exists. `unknown` means the probe could not finish. `reason` says why: `smtp_unreachable` means TCP connected and no SMTP greeting arrived (`mx_valid` is true when the MX host itself was real); other SMTP failures name the port that was tried. `mx_valid` is false when DNS did not produce a public mail host.

## Limits

- **Port 25.** Many networks, including this demo environment and most cloud hosts, block outbound SMTP. A filter that accepts TCP and never sends a greeting is `unknown` with `reason` `smtp_unreachable`, not `valid`. Set `OPENHUNTER_SMTP_PORT` to probe another port and `OPENHUNTER_SMTP_TIMEOUT` to change how long each attempt, including the greeting, is allowed to wait. Set `OPENHUNTER_SMTP=0` to skip the probe and keep the syntax, MX, disposable, and role checks.
- **Catch-all domains.** A domain that accepts every recipient cannot be used to prove an address. Status is `accept_all` and the score stays modest.
- **GitHub quota and terms.** Unauthenticated requests are 60 per hour per IP. A token (`GITHUB_TOKEN` or `GH_TOKEN`) raises that to 5,000. One domain search looks at the org, public members, up to 5 recently pushed public repos, 15 commits each, and up to 12 profiles. Noreply addresses and bot authors are dropped. Use the official REST API only, and follow GitHub's terms.
- **Polite crawling.** `robots.txt` is honored on the company site and on search-result hosts. There is a short delay between requests. The company-site budget is 12 HTML responses, including sitemaps, and 3 PDFs. Web search adds at most 3 queries and 6 pages. Nothing behind a login is fetched.
- **Search engines.** DuckDuckGo's HTML endpoint sometimes answers `202` and returns no links. That is reported and, when no other backend is configured, that query contributes nothing. Brave and SearXNG are optional.
- **Public data only.** A missing email means nothing was published, not that the person has no mailbox. Do not treat a candidate from `email_finder` as a verified address.
- **Cache.** Successful domain searches are cached for 7 days and verifications for 24 hours. `--refresh` bypasses the result cache. The address index is not part of that cache: it accumulates until you delete the database. A search that failed because GitHub, the website, or the search backend could not be reached is not cached.
- **Fake-IP DNS.** Some networks answer every lookup with `198.18.0.0/15` and proxy the real connection. OpenHunter connects by hostname in that case instead of pinning the address. Those addresses, and other private or non-global addresses, are not used as implicit MX hosts. `OPENHUNTER_DNS_MODE=auto` (the default) asks Cloudflare and then Google over DNS-over-HTTPS when the system resolver returns no MX, times out, or only those addresses. `system` stays on the system resolver. `doh` skips it. User-supplied URLs that resolve to `10/8`, `172.16/12`, `192.168/16`, `127/8`, or link-local stay blocked. Set `OPENHUNTER_TRUST_RESOLVER=1` only when that check should be skipped and `HTTPS_PROXY` / `HTTP_PROXY` should be used.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` or `GH_TOKEN` | unset | GitHub API authentication |
| `BRAVE_SEARCH_API_KEY` or `BRAVE_API_KEY` | unset | Use the Brave Search API instead of DuckDuckGo |
| `SEARXNG_URL` | unset | SearXNG base URL, for example `https://search.example` |
| `OPENHUNTER_DB` | `~/.local/share/openhunter/openhunter.db` | SQLite cache, address index, and leads |
| `OPENHUNTER_DNS_MODE` | `auto` | `system` uses the OS resolver. `doh` uses DNS-over-HTTPS (Cloudflare, then Google). `auto` tries the OS resolver and repeats the query over DNS-over-HTTPS on NoAnswer, timeout, or a private/fake-IP answer |
| `OPENHUNTER_SMTP` | on | Set to `0` to skip the RCPT probe |
| `OPENHUNTER_SMTP_PORT` | `25` | TCP port for the SMTP greeting and RCPT probe |
| `OPENHUNTER_SMTP_TIMEOUT` | `5` | Seconds for each DNS query and each SMTP attempt, including the wait for a greeting |
| `OPENHUNTER_DISPOSABLE_FILE` | unset | Extra disposable domains, one per line |
| `OPENHUNTER_LOG` | `WARNING` | Log level |
| `OPENHUNTER_TRUST_RESOLVER` | unset | Set to `1` to skip the public-IP check, connect by hostname, and honor `HTTPS_PROXY` / `HTTP_PROXY` |

## Tests

```bash
pytest
```

The suite covers pattern inference, SMTP interpretation (including a blocked port, a missing SMTP greeting, and a configurable port), DNS and null-MX handling, DNS-over-HTTPS fallback for a Google Workspace MX, rejection of private and fake-IP address fallbacks, fake-IP DNS (`198.18.0.0/15`) and the trusted-resolver opt-in, HTML and PDF extraction, sitemap crawls, DuckDuckGo and Brave search, the GitHub org fallback, the address index, the SQLite cache and lead export, the CLI, and both the in-process and stdio MCP servers.
