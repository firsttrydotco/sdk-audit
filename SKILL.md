---
name: sdk-audit
description: Audit a mobile app's SDK integration (Meta, Adjust, AppsFlyer, TikTok, Branch, etc.) via mitmproxy. Captures traffic, analyzes MMP configuration, detects platform, generates a PDF report with code recommendations. Use when the user mentions auditing SDKs, checking MMP setup, intercepting app traffic, mitmproxy, advanced matching, IDFA tracking, deep links, web-to-app attribution, or wants to know what an app sends to Meta/Facebook/Adjust/AppsFlyer/TikTok/Branch. Triggers (FR + EN) "audit sdk", "check sdk", "mitmproxy", "lance mitmproxy", "intercepte le trafic", "check advanced matching", "est-ce que l'app envoie", "what does the app send", "check attribution", "audit MMP", "sdk-audit", "check IDFA", "check deep links".
---

# SDK Audit via mitmproxy

Intercept an app's network traffic to audit MMP / SDK configuration: advanced matching, custom events, deep links, web-to-app, paywall compliance.

This skill assumes the repo is installed at `~/.claude/skills/sdk-audit/` (see install instructions in the repo README — usually a symlink from a clone of `firsttrydotco/sdk-audit`).

## Phase 1: Capture

Launch mitmproxy in background — **NEVER foreground**, it blocks the conversation:

```bash
bash ~/.claude/skills/sdk-audit/run.sh
```

Run with `run_in_background: true`.

Tell the user: **"You can launch the app. Tell me when you're done."**

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

### 2d. Paywall compliance (Apple 3.1.1 / IAP bypass detection)

If the app is iOS, inspect `captured["payment"]` in the JSON dump. Any entry there = the app talked to a payment processor (Stripe, Paddle, LemonSqueezy, Braintree, Adyen, PayPal, etc.) instead of StoreKit.

Signals to flag:
- **POST to `api.stripe.com/v1/payment_intents`, `/v1/setup_intents`, `/v1/charges`, `/v1/subscriptions`, `/v1/invoices`, `/v1/orders`, or `/checkout/sessions`** from inside the app → direct card charge / subscription renewal, not StoreKit.
- **GET to `js.stripe.com` / `checkout.stripe.com`** from a WebView embedded in the paywall → Stripe Elements or Checkout session.
- **Any Paddle / LemonSqueezy / Adyen / Braintree hit** during a subscription flow.
- **Superwall paywall loaded** (hits to `superwall.me` / `superwallassets.com`) combined with payment processor traffic → Superwall-orchestrated external-payment bypass.

Caveats (don't false-positive):
- **Reader apps** (Netflix, Spotify, Kindle) are allowed to link out — Apple entitlement.
- **Physical goods / services** (Uber, DoorDash) use Stripe legitimately, no StoreKit required.
- **External Link Account Entitlement** (dating apps in some regions) permits external payment with a notice sheet.
- Network traffic alone can't prove UI mimicry of native IAP sheets — that requires a screenshot of the paywall at the moment of purchase.
- **Stripe.js fingerprinting infra** (`js.stripe.com/v3/m-outer-*`, `m.stripe.network/inner.html`, `m.stripe.com/6`) can load even when no actual charge is processed — Superwall WebView paywalls often preload it. Treat as YELLOW (infra present) unless you also see `api.stripe.com/v1/payment_intents` or `/v1/setup_intents` (RED).

### 2e. Cohort-routed paywall (CRITICAL — the real 3.1.1 evasion pattern)

A single capture session can MISLEAD you. Apps using Superwall + MMP attribution commonly route paywalls by cohort:
- **App Review reviewers / organic installs** → Apple StoreKit paywall (safe for review)
- **High-LTV install sources** (Meta Purchase campaigns, TikTok with strong intent signals, retargeting) → Stripe/Paddle paywall (saves 30%)
- **Geo / paying-country buckets** → variant-specific routing

Signals to correlate per session:
- `$paywall_identifier` in Superwall events — the name often leaks intent (`appreview-*`, `organic-*`, `paid-meta-*`, `high-intent-*`). A name like `appreview-...--show-both-plans...` has been observed even when the install was organic — i.e. the app served the reviewer-safe variant.
- `$variant_id` + `$experiment_id` from `confirm_assignments` — a single session only assigns ONE variant; you must test multiple installs to see the variant space.
- AppsFlyer install attribution: `media_source`, `campaign`, `af_ad`, `af_adset` — these are sent to the app backend AND usually forwarded to Superwall as user attributes, feeding cohort assignment.
- Superwall `user_attributes` event body — inspect which MMP fields are forwarded (e.g., `media_source: "Facebook Ads"` → Superwall can gate variants on it).

To really audit an app for 3.1.1 evasion, you need MULTIPLE install sessions:
1. **Organic install** (App Store search) — baseline, usually the safe variant
2. **Paid install from a Meta Purchase campaign** — click a real prod ad, install, open → this is the cohort sellers optimize for an external-payment bypass
3. **TestFlight / Sandbox** — often serves debug variants
4. Compare the `$paywall_identifier` and `$product_id` across sessions. If they differ AND only the paid variant shows Stripe traffic → that's the smoking gun.

One-session audits can only say "this cohort got variant X". They CANNOT prove the app is compliant overall — only that THIS user path was. Always note this limitation in the report.

In the report, add a **"Paywall Compliance"** section with:
- List of payment processor hosts hit + timestamps
- Whether a paywall SDK (Superwall/RevenueCat/Adapty) is also present
- Paywall identifier + variant/experiment IDs observed
- Which MMP attributes the app forwards to the paywall SDK
- Verdict: `[OK]` (no external payment traffic, StoreKit confirmed), `[REVIEW]` (external payment infra loaded but no charge, variant name suspicious), `[!!! HIGH RISK]` (actual payment_intents POST + subscription app + no entitlement).
- **Session scope disclaimer**: explicitly state "this audit covers variant X; other cohorts may see different paywalls".

### 2f. IDFA & ATT status (ALWAYS report on iOS — never skip)

The single most common confusion in these audits: **"the app doesn't collect the IDFA"** vs **"the app collects it but it comes out zeroed"**. These are *different findings*. ALWAYS answer **both** questions separately and state both conclusions explicitly — never just say "no IDFA".

**Q1 — Is the IDFA collection plumbing present & enabled?** (does the app even ask for it and ship it)
- Meta `/activities` body: `advertiser_id_collection_enabled: "1"` **and** an `advertiser_id` field present → plumbing ON.
- RevenueCat `/attributes` body: an `$idfa` attribute present → plumbing ON (RC also sends `$idfv`, `$fbAnonId`, `$firebaseAppInstanceId`).
- Adjust `/session`: `idfa` param present → plumbing ON.
- TikTok / others: catch-all IDFA field in the batch body.

**Q2 — Is a USABLE (non-zero) IDFA actually transmitted?**
- `00000000-0000-0000-0000-000000000000` (all zeros) → **no usable IDFA** (ATT not authorized). This is the value iOS hands the SDK whenever ATT ≠ authorized.
- A real non-zero UUID in `advertiser_id` / `$idfa` / Adjust `idfa` → real IDFA, ATT was authorized.
- Don't confuse the **IDFV** (`$idfv`, Adjust `idfv`, vendor identifier) with the IDFA — the IDFV is *always* available, needs no consent, and circulates everywhere (RC, Meta `anon_id`, Adjust, Amplitude, PostHog). Seeing a non-zero IDFV does NOT mean the IDFA was collected.

**Read the ground truth — the ATT status.** Best explicit source is Adjust `att_status` (param or body):

| `att_status` | meaning |
|---|---|
| `0` | **notDetermined** — the ATT prompt was never answered/shown |
| `1` | restricted (parental controls / MDM / supervised) |
| `2` | **denied** — user tapped "Ask App Not to Track" (or the device-level toggle is OFF) |
| `3` | **authorized** — user tapped "Allow" → real IDFA flows |

If Adjust isn't in the capture, infer from the IDFA value: any non-zero IDFA ⇒ status was authorized; an all-zeros IDFA ⇒ status was *not* authorized (but you can't tell notDetermined from denied without `att_status`).

**The "I didn't see the ATT popup" diagnosis** (recurs constantly — handle it precisely):
- On a **fresh install**, `att_status = 0` (notDetermined) means the app **never called** `ATTrackingManager.requestTrackingAuthorization()` on the screens you exercised. If it had, iOS would have shown the prompt. So "no popup" + fresh install + status 0 ⇒ **the app doesn't trigger the ATT flow** → the IDFA stays zeroed *forever*, regardless of the plumbing being enabled. Collection is "plumbed but **dead**".
- Distinguish the three cases — do NOT conflate them:
  - `0` after fresh install, no popup → app never requests ATT (most likely when the user reports no popup).
  - `2` (denied) → user refused **or** the global iOS toggle *Settings → Privacy & Security → Tracking → "Allow Apps to Request to Track"* is OFF. The toggle-off case ALSO yields `2` **without showing any popup** — so `2 ≠ 0`. If the user "saw no popup" but status is `2`, suspect the global toggle, not the app.
  - `3` (authorized) → real IDFA present, everything works.
- **Before concluding "the app never requests ATT", rule out a deferred prompt.** Many apps fire `requestTrackingAuthorization` *after* onboarding / signup, not on the splash. If status is `0`, tell the user to push deeper into the app (finish onboarding, create an account) and re-capture. Only after a deep session still shows `0` is "never requests ATT" confirmed.

**Meta inconsistency to flag:** Meta frequently sends `advertiser_tracking_enabled: "1"` while ATT is *not* authorized (IDFA zeroed). That flag should mirror the real ATT status; sending `1` alongside a zeroed `advertiser_id` is a contradictory signal that degrades Meta attribution/dedup. Call it out as a [REVIEW] item whenever you see `advertiser_tracking_enabled:1` + zeroed IDFA + `att_status` ≠ 3.

**Always write the verdict as two explicit lines** (in both chat and the report), e.g.:
- `IDFA collection: ENABLED in Meta SDK + RevenueCat (plumbing present, advertiser_id_collection_enabled=1, $idfa attribute sent).`
- `IDFA transmitted: ZEROED — att_status=0 (notDetermined); app never triggers the consent prompt → no usable IDFA will ever be sent until it calls requestTrackingAuthorization().`

## Phase 3: Report

Generate the PDF directly (don't ask, don't generate Markdown separately):

```bash
python3 ~/.claude/skills/sdk-audit/generate_report.py --platform <detected> --app-name <name>
```

Use a custom Python + fpdf2 script if the report needs sections beyond the default (e.g. a web-to-app deep dive, a critical-warning banner about SDK init order).

**PDF specs:**
- Output: `~/Downloads/{app_name}-sdk-audit-{YYYY-MM-DD}.pdf`
- Fonts: Arial TTF, loaded from `/System/Library/Fonts/Supplemental/` (macOS default). On Linux/Windows, set `AUDIT_FONT_DIR` to a directory containing `Arial.ttf`, `Arial Bold.ttf`, `Arial Italic.ttf`, `Courier New.ttf` (or equivalents).
- `fpdf2` is required (`pip install fpdf2`). Ignore the "Core font already added" warning.
- Arial doesn't support emoji — use `[!]` or `ATTENTION:` instead of warning glyphs.

**Report structure:**
1. **Title + metadata** (app name, bundle ID, version, date, platform, test scenario)
2. **Critical warning banner** (if applicable — e.g. SDK not initialized before paywall)
3. **Legal Basis for This Audit** (MANDATORY — front matter, before the findings; see below)
4. **Results per SDK** (status lines: `[OK]` / `[KO]` for each check) — **plus, for every SDK, an "Identifiers sent" inventory** listing the *raw identifier values* it actually transmits, not just OK/KO. `generate_report.py` emits this automatically (via `collect_identifiers` / `collect_meta_device` / `collect_rc_attributes`); a manual report MUST include it too. Surface at minimum:
   - **Meta**: `anon_id` (fbAnonId), `advertiser_id` (IDFA, annotate zeroed), `app_user_id` (flag when it equals the RevenueCat/Firebase user ID — strongest cross-service link), `access_token` → FB App ID, the decoded `extinfo` device fingerprint (model, OS, locale, timezone, screen, disk), declared `url_schemes`, and the tracking flags (`advertiser_id_collection_enabled`, `advertiser_tracking_enabled`).
   - **Adjust**: `idfv`, `idfa`, `gps_adid`, `adid`, `fb_anon_id`, `external_device_id`, `app_token`, `bundle_id`, `environment`, `att_status` (with its decoded meaning).
   - **AppsFlyer / TikTok / Branch**: their device/user IDs (`uid`, `customer_user_id`, `idfa/idfv`, `identity`, etc.).
   - **RevenueCat**: every `$`-attribute (`$idfa`, `$idfv`, `$fbAnonId`, `$firebaseAppInstanceId`, `$appsflyerId`, `$adjustId`, …) — these reveal which MMPs are wired in.
   Don't redact values captured from your own device, but do annotate zeroed IDFAs and split `access_token` into FB App ID + truncated client token. Long values render as short per-field lines so PDF wrapping can't break.
5. **IDFA & ATT status** (MANDATORY on iOS — see 2f). Always include the two explicit verdict lines: (a) is IDFA collection plumbed/enabled per SDK, (b) is a usable non-zero IDFA actually transmitted, with the `att_status` value and its meaning. If status is `0`/`2`, state plainly that no usable IDFA flows and why (app never requests ATT vs. denied/global toggle). Flag the `advertiser_tracking_enabled:1` + zeroed-IDFA inconsistency here.
6. **Paywall Compliance** (Apple 3.1.1 — see 2d/2e; include the session-scope disclaimer)
7. **Web-to-App analysis** (deep links, campaign attribution)
8. **Recommendations** (numbered, prioritized, with platform-specific code examples)
9. **Next steps** (prioritized action plan)
10. **Appendix** (raw data counts, proof of hidden SDKs like `$appsflyerId` in RevenueCat)

**Two distinct "legal" things — don't conflate them:**
- *Optional* — privacy/compliance **findings about the app** (missing CMP, GDPR consent, ATT
  mismatch). If you include these, title that section **"Privacy Compliance"**, not "Legal".
- *Mandatory* — the **"Legal Basis for This Audit"** section, which justifies the auditor's
  right to capture the traffic. ALWAYS include it, in every report, as **front matter** —
  immediately after the title/metadata (and warning banner, if any), before the findings.
  This matches `generate_report.py`, which emits it as its first section right after the
  title. Use the exact 3-paragraph text below verbatim — it is the same wording shared by
  `generate_report.py` (`LEGAL_PARA_1/2/3`):

> This analysis was performed solely by inspecting network traffic emitted by a copy of the
> {app_name} application installed on a device owned by the author, over an internet connection
> owned by the author. No application code was modified, no third-party infrastructure was
> accessed, and no user data other than the author's own test account was collected.
>
> Inspecting outbound network traffic from one's own device is not restricted under EU or
> French law. No offence under the French Code pénal (Art. 323-1 et seq., STAD) or under EU
> Directive 2013/40/EU on attacks against information systems arises, as no third-party system
> was accessed. As a data subject under the GDPR (Art. 15 right of access, Art. 5(1)(a)
> transparency principle), the author has a right to understand what personal data is
> transmitted from their device. No reverse engineering of the application's binaries was
> performed (Directive 2009/24/EC); the capture relied solely on standard TLS MITM with a
> user-installed root certificate.
>
> This report is shared in good faith to help improve the tracking implementation and is not a
> public disclosure.

The `generate_report.py` script already emits this section. If you generate the PDF manually
with fpdf2, you MUST add it yourself — it is the most common omission.

**Code examples** must be in the detected platform language (Swift / Kotlin / Unity C# / React Native JS).

## Sharing the report (clipboard / Markdown)

If asked to copy the report to the clipboard on macOS, produce the Markdown and pipe it through
`pbcopy` **with a UTF-8 locale forced**:

```bash
LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 pbcopy < report.md
```

Plain `pbcopy < report.md` reads the bytes in the shell's legacy encoding (often Mac Roman),
so it stores mojibake on the pasteboard — every non-ASCII character is corrupted (e.g. an
em-dash or an accented letter). This is a corruption at copy time, not a font issue, so it
pastes wrong even into UTF-8-capable apps. Always force the locale.

If the destination still mojibakes UTF-8 text after a correct copy, that destination cannot
decode UTF-8 — only then fall back to a pure-ASCII variant (`[OK]` / `[KO]` / `[!]`, `-` for em
dashes, unaccented letters).
