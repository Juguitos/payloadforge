# ⚡ PayloadForge — Firefox Extension

> A browser extension port of [PayloadForge](https://github.com/Juguitos/payloadforge) by [@Juguitos](https://github.com/Juguitos).
> Build, mutate and **inject** WAF-bypass payloads directly into the page you are testing — no server, no copy-paste round trips.

![Manifest](https://img.shields.io/badge/Manifest-V3-blue?style=flat-square)
![Firefox](https://img.shields.io/badge/Firefox-121%2B-FF7139?style=flat-square&logo=firefoxbrowser&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Why an extension?

The original PayloadForge is a great web app, but a browser extension can do something a web page cannot: **write a payload straight into the input you are auditing**. This port keeps the full payload library and mutation engine, and adds in-page injection plus quality-of-life features.

## ✨ Features

**Everything from PayloadForge:**
- **14 categories / 204 payloads** — XSS, SQLi, SSTI, LFI, IDOR, CmdInj, CORS, JWT, LDAP, NoSQL, SSI, SSRF, XXE, Clickjacking (labeled `PATT` = PayloadsAllTheThings or `PF` = PayloadForge original)
- **13 mutation techniques** + **7 WAF bypass profiles** (Cloudflare, ModSecurity, AWS, Akamai, F5, Imperva, Generic)
- **JWT editor** — decode, quick attacks (alg:none, role escalation, kid traversal…), forge
- **Clickjacking demo** — live iframe framability tester with overlay PoC
- **Export** — `.txt` / `.json` for Burp Intruder / ffuf

**New in the extension:**
- 🖱️ **Right-click → insert payload** into any text field, organized by category
- ⇥ **"Insert in page"** buttons in the popup (library, editor and every mutation)
- 🔁 **Placeholder wizard** — set `TARGET` / `ATTACKER` / `OAST` once; they are auto-substituted in everything you copy or inject
- ★ **Favorites** and ⟲ **recent** payloads, persisted locally
- ⌨️ **Keyboard shortcuts** — `Ctrl+Shift+P` open, `Ctrl+Shift+Y` re-inject last payload
- 🌓 Light / dark theme

## 🔒 Permissions (and why)

| Permission | Why |
|---|---|
| `activeTab` + `scripting` | Insert a payload into the **current** tab **only when you ask** (menu click, button, or shortcut). No standing access to your browsing. |
| `contextMenus` | The right-click "insert payload" menu. |
| `storage` | Save favorites, recents and placeholder values locally. |
| `clipboardWrite` | Copy buttons. |

There is **no `host_permissions` for all sites** and **no network access** — the extension never phones home.

## 🚀 Install

### Temporary (for testing / development)
1. Clone this repo.
2. Open Firefox → `about:debugging#/runtime/this-firefox`
3. **Load Temporary Add-on…** → pick `manifest.json`.

### Packaged `.xpi`
```bash
./build.sh          # produces web-ext-artifacts/payloadforge.zip
```
Rename to `.xpi`. For permanent install it must be signed via [AMO](https://addons.mozilla.org/developers/) (`web-ext sign`) unless you use Firefox Developer/Nightly with `xpinstall.signatures.required = false`.

### Permanent install (signed)
See **[SIGNING.md](SIGNING.md)** — get free Mozilla API credentials, run `./sign.sh`, then install the resulting signed `.xpi` from `about:addons`. This is the only way to install permanently on Firefox **stable**.

> Works on Chromium too with a minor manifest change (swap `background.scripts` for a `service_worker`).

## ⚠️ Disclaimer

For **authorized security testing and education only**. Use only on systems you own or have explicit written permission to test. The authors are not responsible for misuse.

## 🙏 Credits

- Original tool & payloads: [PayloadForge](https://github.com/Juguitos/payloadforge) by [@Juguitos](https://github.com/Juguitos)
- Payload corpus: [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (MIT)

## 📄 License

MIT — see [LICENSE](LICENSE).
