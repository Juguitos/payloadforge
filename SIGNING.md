# 🔏 Making PayloadForge permanent (signed install on Firefox stable)

Firefox **release/stable** only installs extensions **signed by Mozilla**. Signing is
free and automatic for self-distributed ("unlisted") add-ons. You do **not** have to
list it publicly on the add-ons site.

You end up with a signed `payloadforge-1.0.0.xpi` that installs permanently.

---

## Step 1 — Get Mozilla API credentials (once)

1. Sign in / create a free account at <https://addons.mozilla.org/>.
2. Go to <https://addons.mozilla.org/developers/addon/api/key/>.
3. Click **Generate new credentials**. You get:
   - **JWT issuer** (looks like `user:12345:67`)
   - **JWT secret** (a long hex string)

Keep the secret private — treat it like a password.

## Step 2 — Install the tooling (once)

You need [Node.js](https://nodejs.org/) (LTS). Then no global install is required —
we run `web-ext` via `npx`.

## Step 3 — Sign

From the extension folder (the one containing `manifest.json`):

```bash
# put your credentials in env vars so they never get hard-coded or committed
export AMO_JWT_ISSUER="user:12345:67"
export AMO_JWT_SECRET="your-long-secret-here"

./sign.sh
```

`sign.sh` runs:

```bash
npx --yes web-ext@8.3.0 sign \
  --channel=unlisted \
  --api-key="$AMO_JWT_ISSUER" \
  --api-secret="$AMO_JWT_SECRET"
```

After a minute, the signed file appears in `web-ext-artifacts/`, e.g.
`web-ext-artifacts/payloadforge-1.0.0.xpi`.

> Each new upload needs a **new `version`** in `manifest.json` (1.0.0 → 1.0.1 …),
> otherwise Mozilla rejects it as a duplicate.

## Step 4 — Install the signed `.xpi` permanently

1. Open Firefox → `about:addons`
2. Click the gear ⚙ → **Install Add-on From File…**
3. Pick `web-ext-artifacts/payloadforge-1.0.0.xpi`
4. Confirm. It now survives restarts. ✅

(You can also just drag the `.xpi` onto the Firefox window.)

---

## Alternatives (no Mozilla account needed)

| Method | Permanent? | Notes |
|---|---|---|
| **Firefox Developer Edition / Nightly** | ✅ | Set `xpinstall.signatures.required = false` in `about:config`, then install the unsigned `.xpi` (run `./build.sh`, rename `.zip` → `.xpi`). Does **not** work on stable. |
| **Firefox ESR + Enterprise policy** | ✅ | For managed/enterprise machines only. |
| **Temporary add-on** | ❌ | Via `about:debugging`; gone on restart. Fine for quick testing. |

The **signed `.xpi` (Steps 1–4)** is the only way to get a permanent install on
ordinary Firefox stable.
