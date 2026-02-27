# ⚡ PayloadForge — WAF Bypass Laboratory

> A self-hosted PHP tool for pentesters to build, mutate, and export payloads with WAF bypass profiles.

![PHP](https://img.shields.io/badge/PHP-8.0+-777BB4?style=flat-square&logo=php&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-3.0.0-red?style=flat-square)
![Category](https://img.shields.io/badge/Category-Pentesting-orange?style=flat-square)
![Credits](https://img.shields.io/badge/Payloads-PayloadsAllTheThings-blue?style=flat-square)
![Visitor Count](https://komarev.com/ghpvc/?username=Juguitos&color=00ff41&label=Visitors&style=flat-square)
![GitHub stars](https://img.shields.io/github/stars/Juguitos/payloadforge?style=flat-square&color=00ff41&labelColor=000000)
![GitHub forks](https://img.shields.io/github/forks/Juguitos/payloadforge?style=flat-square&color=ff8800&labelColor=000000)

> **Payload sources:** Curated payloads from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by [@swisskyrepo](https://github.com/swisskyrepo) (MIT License) — combined with original PayloadForge payloads. Each payload is labeled `PATT` or `PF` in the UI.

---

## 📸 Features

- **14 payload categories** — XSS, SQLi, SSTI, LFI, IDOR, CmdInj, CORS, JWT, LDAP, NoSQL, SSI, SSRF, XXE, Clickjacking
- **204 curated payloads** with tags, descriptions and source attribution
- **Dual payload sources** — `PATT` (PayloadsAllTheThings) + `PF` (PayloadForge originals), labeled in the UI
- **13 mutation techniques** — URL Encode, Double URL Encode, Base64, Hex, Unicode Escape, HTML Entity, Case Alternation, Null Byte, SQL Comment Break, Tab Substitute, Newline Inject, JSON Unicode, HTML Hex
- **7 WAF bypass profiles** — Cloudflare, ModSecurity, AWS WAF, Akamai, F5 BIG-IP, Imperva, Generic
- **🔑 JWT Editor** — Decode, modify claims, run quick attacks (alg:none, kid traversal, role escalation) and forge tokens directly in the browser
- **🖱️ Clickjacking Demo** — Live iframe tester with transparent overlay PoC to visually confirm X-Frame-Options presence or absence
- **Export** — `.txt` and `.json` formats ready for Burp Intruder / ffuf wordlists
- **Zero dependencies** — pure PHP 8.0+, no Composer, no Node
- **Matrix rain background** because style matters

---

## 🚀 Quick Start

### Option 1 — Docker (recommended)

```bash
git clone https://github.com/Juguitos/payloadforge.git
cd payloadforge
docker-compose up -d
```
Open: [http://localhost:8080](http://localhost:8080)

### Option 2 — PHP built-in server

```bash
git clone https://github.com/Juguitos/payloadforge.git
cd payloadforge
php -S 0.0.0.0:8080
```
Open: [http://localhost:8080](http://localhost:8080)

### Option 3 — Apache / Nginx

Copy files to your web root. Requires PHP 8.0+.

---

## 🛠️ Usage

1. **Select a category** from the top nav
2. **Browse payloads** in the left sidebar — click one to load it
3. Go to the **CUSTOM** tab:
   - Edit the payload freely
   - Optionally select a **WAF Profile** to auto-load bypass mutations
   - Or toggle individual **Mutation** chips manually
4. Click **⚡ GENERATE MUTATIONS**
5. In the **MUTATIONS** tab, copy individual results or export all as `.txt` / `.json`

> **JWT category** opens a dedicated token editor instead of the mutation form.  
> **Clickjacking category** opens a live iframe demo tool instead of the mutation form.

---

## 📦 Payload Categories

| Category     | Count | Use Case |
|--------------|-------|----------|
| XSS          | 20    | Reflected, DOM, stored XSS, polyglots, cookie exfil, angular SSTI |
| SQLi         | 20    | Auth bypass, UNION, blind boolean/time, error-based, file read/write |
| SSTI         | 18    | Jinja2, Twig, Freemarker, Smarty, ERB, Tornado, Velocity, Mako |
| LFI          | 18    | Path traversal, PHP wrappers, log poisoning, Windows paths, phar/zip |
| IDOR         | 16    | Sequential IDs, UUID, mass assignment, GraphQL, S3, param pollution |
| CmdInj       | 16    | Semicolon/pipe/backtick chains, IFS bypass, glob, reverse shells, OOB |
| CORS         | 12    | Origin reflection, null origin, subdomain attacks, fetch/XHR PoC |
| JWT          | 12    | alg:none, kid traversal, jku/x5u injection, weak secret brute |
| LDAP         | 12    | Auth bypass, wildcard inject, blind extraction, DN inject, filter escape |
| NoSQL        | 12    | MongoDB operators, $where JS, Redis, CouchDB, GraphQL inject |
| SSI          | 12    | exec cmd, include virtual/file, printenv, reverse shell |
| SSRF         | 16    | Localhost, AWS/GCP/Azure metadata, file/dict/gopher, IP encoding bypass |
| XXE          | 12    | File read, SSRF, OOB exfil, billion laughs, SVG/XLSX, XInclude |
| Clickjacking | 8     | Iframe PoC, transparent overlay, form hijack, detection, mitigations |

---

## 🔑 JWT Editor

The JWT category includes an interactive token editor:

- **Decode** any JWT into editable header and payload JSON
- **Quick attacks** with one click:
  - Set `alg: none` (unsigned token bypass)
  - Escalate role to `admin`
  - Remove expiry (`exp: 9999999999`)
  - Inject `isAdmin: true`
  - `kid` path traversal (`../../dev/null`)
  - `kid` SQL injection
- **Forge** — rebuild the token with modified claims (keep original sig or strip it for alg:none)
- **Copy** forged token directly to clipboard

---

## 🖱️ Clickjacking Demo

The Clickjacking category includes a live demo tool:

- Enter any target domain and click **TEST**
- An iframe attempts to load the target — the status bar shows **VULNERABLE** (loaded) or **PROTECTED** (blocked)
- Toggle **OVERLAY** to render a transparent attack layer with an animated fake button over the real page
- Info cards explain the vulnerability, mitigations, and how to use the PoC payloads in reports

---

## ⚙️ Mutation Techniques

| Technique | Example |
|-----------|---------|
| URL Encode | `%3Cscript%3E` |
| Double URL Encode | `%253Cscript%253E` |
| Base64 | `PHNjcmlwdD4=` |
| Hex Encode | `%3C%73%63%72%69%70%74%3E` |
| HTML Entity | `&lt;script&gt;` |
| Unicode Escape | `\u003cscript\u003e` |
| Case Alternation | `<sCrIpT>` |
| Null Byte | `payload%00` |
| SQL Comment Break | `SELECT/**/1` |
| Tab Substitute | `SELECT%09` |
| Newline Inject | `SELECT%0a` |
| JSON Unicode | `\u003cscript\u003e` (JSON-safe) |
| HTML Hex Entities | `&#x3C;script&#x3E;` |

---

## 🛡️ WAF Bypass Profiles

| Profile | Mutations Applied |
|---------|-------------------|
| Cloudflare | URL Encode, Case Alternation, HTML Entity, Unicode Escape |
| ModSecurity | Double URL Encode, Null Byte, SQL Comment, Hex Encode |
| AWS WAF | Base64, HTML Entity, Tab Substitute, Newline Inject |
| Akamai | Unicode Escape, Double URL Encode, Case Alternation, Null Byte |
| F5 BIG-IP | Hex Encode, HTML Entity, Tab Substitute, URL Encode |
| Imperva | Double URL Encode, HTML Hex, Case Alternation, Tab Substitute |
| Generic | URL Encode, Base64, HTML Entity, Hex Encode |

---

## 🐳 Docker Details

```yaml
# docker-compose.yml already included
# Default port: 8080
# PHP version: 8.2-apache
```

To change the port:
```yaml
ports:
  - "YOUR_PORT:80"
```

---

## 📁 Project Structure

```
payloadforge/
├── index.php           # Main application (single-file architecture)
├── docker-compose.yml  # Docker deployment
├── Dockerfile          # PHP + Apache container
├── .gitignore          # Git ignore rules
├── LICENSE             # MIT License
└── README.md           # This file
```

---

## 🤝 Contributing

Contributions are welcome! To add payloads:

1. Fork the repo
2. Edit the `$PAYLOADS` array in `index.php`
3. Add your payload with `id`, `name`, `payload`, `tags`, and `source`
4. Set `source` to `"PF"` for original payloads
5. Submit a pull request

To add mutation techniques, add a `case` to the `mutate()` function and register it in `$MUTATION_LABELS`.

To add a new category, add it to `$PAYLOADS` and `$CATEGORY_COLORS`. For categories that need a custom UI instead of the mutation form (like JWT or Clickjacking), add a conditional block in the `custom` tab section of the template.

---

## 🙏 Credits

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) by [@swisskyrepo](https://github.com/swisskyrepo) — MIT License
- PayloadForge original payloads and tooling by [@Juguitos](https://github.com/Juguitos)

---

## ⚠️ Disclaimer

> PayloadForge is intended for **authorized security testing** and **educational purposes only**.  
> Use only on systems you own or have explicit written permission to test.  
> The authors are not responsible for any misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

Made with ⚡ by [@Juguitos](https://github.com/Juguitos) for the pentesting community
