---
name: sdk-audit
description: Audit a mobile app's SDK integration (Meta, Adjust, AppsFlyer, TikTok, Branch, etc.) via mitmproxy. Captures traffic, analyzes MMP configuration, detects platform, generates a PDF report with code recommendations. Use when the user mentions auditing SDKs, checking MMP setup, intercepting app traffic, mitmproxy, advanced matching, IDFA tracking, deep links, web-to-app attribution, or wants to know what an app sends to Meta/Facebook/Adjust/AppsFlyer/TikTok/Branch. Triggers (FR + EN) "audit sdk", "check sdk", "mitmproxy", "lance mitmproxy", "intercepte le trafic", "check advanced matching", "est-ce que l'app envoie", "what does the app send", "check attribution", "audit MMP", "sdk-audit", "check IDFA", "check deep links".
---

# SDK Audit via mitmproxy

Intercept an app's network traffic to audit MMP / SDK configuration: advanced matching, custom events, deep links, web-to-app.

This skill assumes the repo is installed at `~/.claude/skills/sdk-audit/` (see install instructions in the repo README — usually a symlink from a clone of `firsttrydotco/sdk-audit`).

## Phase 1: Capture

Launch mitmproxy in background — **NEVER foreground**, it blocks the conversation:

```bash
bash ~/.claude/skills/sdk-audit/run.sh
```

Run with `run_in_background: true`.

Tell the user: **"Tu peux lancer l'app. Dis-moi 'c'est bon' quand t'as fini."**

When the user signals done (or you're asked to auto-stop after enough traffic):

```bash
pkill -f mitmdump
```

Capture file: `/tmp/mitmproxy_capture.json` (written continuously, atomic — survives kill).

If the capture file is empty or only contains a few entries, the most likely causes are:
1. Phone proxy not pointing at the host (check IP + port 8080)
2. mitmproxy CA cert not installed or not trusted on the device
3. The app pins certificates (no fix in this skill — it's an app-level limitation)

## Phase 2: Analysis

Read `/tmp/mitmproxy_capture.json` and check every category.

### 2a. Detect app platform (DON'T ask the user)

Deduce from traffic signals:

| Signal | Where | Value → Platform |
|--------|-------|-----------------|
| Intercom `device_data.sdk_type` | `other_sdks` body | `intercom-sdk-native` → Swift, `intercom-sdk-react-native` → React Native, `intercom-sdk-unity` → Unity |
| TikTok `library.name` | `other_sdks` body | `tiktok-business-ios-sdk` → native iOS, `tiktok-business-unity-sdk` → Unity |
| Meta `extinfo[0]` | `meta` body | `"i2"` → iOS native, `"a2"` → Android native |
| RevenueCat attributes | `other_sdks` body | `$rcFramework` value if present |
| URL schemes | `meta` body | Google OAuth client IDs suggest native |

If no strong signal, default to Swift (iOS) or Kotlin (Android) based on `extinfo`.

### 2b. Check each SDK

**Meta SDK:**
- Present? (any request to `facebook.com`)
- `ud` field in POST `/activities` → Advanced Matching (empty `{}` = NOT configured)
- `custom_events` field → decode JSON, check for business events (purchase, startTrial, completeRegistration) vs auto events (`fb_mobile_*`, `fb_sdk_*`)
- If NO `/activities` POST at all → SDK is integrated but not tracking (config requests only)

**AppsFlyer:**
- Present? (requests to `appsflyer.com`) — if 0 requests, check RevenueCat attributes for `$appsflyerId` (proves SDK is embedded but not communicating)
- `customer_user_id` → user identification
- `sha256_email`, `emails` → Advanced Matching
- `af_dp`, `deep_link_value`, `campaign`, `media_source` → web-to-app / deep links
- In-app events (POST `/inappevent/`)

**Adjust:**
- `partner_params` / `callback_params` → user data
- `event_token` → custom events
- `fb_anon_id` → Meta link
- `last_skan_update` → SKAdNetwork

**TikTok:**
- Detected via catch-all IDFA on `analytics.us.tiktok.com`
- Batch events: check for business events vs auto (LaunchAPP, Identify)
- `external_id` in context → user identification
- No email/phone = no advanced matching

**Branch:**
- Requests to `branch.io`, `bnc.lt`, `app.link`
- `identity` / `developer_identity` → user identification
- `/open`, `/install` paths → deep link resolution

**RevenueCat:**
- Subscriber path: named ID = identified, `$RCAnonymousID` = anonymous
- Attributes body: check for `$appsflyerId`, `$adjustId`, `$mixpanelDistinctId` (reveals which MMPs are integrated even if no direct traffic was captured)

**Other SDKs:**
- Intercom, Customer.io, Firebase, Crashlytics, Superwall, Adapty, Amplitude, Mixpanel, Segment, PostHog, Sentry — note presence
- Any UNKNOWN host sending IDFA/IDFV → flag it

### 2c. Web-to-App analysis

Check ALL MMP traffic for:
- Deep link params: `af_dp`, `af_web_dp`, `deeplink`, `deep_link_value`, `link_url`
- Campaign attribution: `campaign`, `media_source`, `pid`, `af_channel`, `c`
- Retargeting: `is_retargeting`, `retargeting_conversion_type`, `af_reengagement_window`
- Click IDs: `click_id`, `clickid`, `install_referrer`

If zero web-to-app signals → flag as "web-to-app attribution not configured".

## Phase 3: Report

Generate the PDF directly (don't ask, don't generate Markdown separately):

```bash
python3 ~/.claude/skills/sdk-audit/generate_report.py --platform <detected> --app-name <name>
```

Use a custom Python + fpdf2 script if the report needs sections beyond the default (e.g. web-to-app deep dive, critical warning banner about SDK init order).

**PDF specs:**
- Output: `~/Downloads/{app_name}-sdk-audit-{YYYY-MM-DD}.pdf`
- Fonts: PDF built-in Helvetica + Courier — no TTF, no setup, works on macOS / Linux / Windows.
- `fpdf2` is required (`pip install fpdf2`).
- Encoding is Latin-1 (covers French accents). Em-dash, ellipsis, curly quotes and euro are auto-translated to ASCII equivalents — don't bother emitting Unicode typography. No emoji either; use `[!]` or `ATTENTION:` instead of ⚠.

**Report structure:**
1. **Title + metadata** (app name, bundle ID, version, date, platform, test scenario)
2. **Critical warning banner** (if applicable — e.g. SDK not initialized before paywall)
3. **Results per SDK** (status lines: `[OK]` / `[KO]` for each check)
4. **Web-to-App analysis** (deep links, campaign attribution)
5. **Recommendations** (numbered, prioritized, with platform-specific code examples)
6. **Next steps** (prioritized action plan)
7. **Appendix** (raw data counts, proof of hidden SDKs like `$appsflyerId` in RevenueCat)

**Code examples** must be in the detected platform language (Swift / Kotlin / Unity C# / React Native JS).
