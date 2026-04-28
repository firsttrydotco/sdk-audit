# sdk-audit

Most mobile user acquisition managers never verify what their developer's Meta SDK actually sends.

They assume "it's integrated" means "it works."

I built a Claude Code prompt that runs a full SDK & attribution audit on any mobile app using mitmproxy.

Plug it in, capture 1 session on your device, and it tells you exactly what fires, what's silent, and what's missing for AEM eligibility.

Takes 10 minutes. Beats weeks of back-and-forth with your dev team. Before you blame iOS privacy for your ROAS.

<img width="500" height="500" alt="1776183228871" src="https://github.com/user-attachments/assets/8dd5c8d3-1831-407d-9b37-77d625879120" />



Audit a mobile app's MMP / SDK integration by intercepting its network traffic with [mitmproxy](https://mitmproxy.org), then generate a PDF report with status checks and code recommendations.

Useful when you want to know — without source-code access — whether an app:

- ships Meta / AppsFlyer / Adjust / Branch / TikTok / Singular / Kochava / Tenjin SDKs
- forwards Advanced Matching (hashed email/phone) to Meta and AppsFlyer
- sends business custom events (purchase, trial start, registration) or only auto-events
- is wired for deep links / web-to-app attribution
- identifies the user in RevenueCat, Branch, AppsFlyer (or stays anonymous)
- talks to any other unexpected SDK (paywall, CRM, analytics, A/B, error tracking)

The capture script keeps **all** traffic and classifies it post-hoc, so unexpected SDKs (Superwall, Adapty, Customer.io, Intercom, Braze, Amplitude, Mixpanel, Segment, PostHog, etc.) show up automatically.

## How it works

1. `run.sh` launches `mitmdump` with the `capture.py` addon.
2. You drive the app on a physical device whose HTTP proxy points at your machine.
3. Every request is parsed (JSON / form-urlencoded), labeled by SDK, and appended to `/tmp/mitmproxy_capture.json` atomically.
4. `generate_report.py` reads that file and produces a PDF (and Markdown) audit in `~/Downloads/`.

```
phone (proxy → your-mac:8080)
        │
        ▼
 mitmdump + capture.py  ──►  /tmp/mitmproxy_capture.json
                                       │
                                       ▼
                          generate_report.py  ──►  ~/Downloads/<app>-sdk-audit-<date>.pdf
```

## Prerequisites

- macOS, Linux, or Windows
- Python 3.9+
- A physical iOS or Android device, network-reachable from the host
- `mitmproxy` installed (`brew install mitmproxy`, `pip install mitmproxy`, or your OS package manager)

```bash
git clone git@github.com:firsttrydotco/sdk-audit.git ~/sdk-audit
cd ~/sdk-audit
pip install -r requirements.txt
```

PDF generation works out of the box on all three OSs with no font setup. The report uses fpdf2's built-in **Helvetica** and **Courier** — these are PDF base-14 fonts, guaranteed present in every PDF reader, so no TTF files are bundled or required.

## Networking: how the phone reaches your Mac

The phone needs to send its HTTP traffic to your Mac on port `8080`. Three ways to make that happen, ranked by how reliably they "just work":

### Option A — Tailscale (recommended)

[Tailscale](https://tailscale.com) gives both machines a stable private IP that follows you across networks (home Wi-Fi, coffee shop, conference, hotspot — even when the two devices are on completely different networks). Once set up, you never touch the proxy config again.

1. **Install on your Mac**: `brew install --cask tailscale`, launch the app, sign in.
2. **Install on the phone**: Tailscale app from the App Store / Play Store, sign in with the same account.
3. **Get your Mac's Tailscale IP**:
   ```bash
   tailscale ip -4
   # → 100.x.y.z
   ```
   Or read it from the menu-bar app.
4. **On the phone**: Settings → Wi-Fi → (i) next to your network → Configure Proxy → Manual:
   - Server: the `100.x.y.z` Tailscale IP from step 3
   - Port: `8080`
5. Make sure Tailscale is **active** on the phone (the app shows "Connected") whenever you want to capture.

This works even when the phone is on cellular — no shared Wi-Fi required.

> If `tailscale ip -4` returns nothing, the daemon isn't running. On macOS: open the Tailscale app and click "Connect". If `tailscale` isn't on `$PATH`, the GUI app keeps the binary at `/Applications/Tailscale.app/Contents/MacOS/Tailscale` — easier to read the IP from the menu bar.

### Option B — Same Wi-Fi network

Phone and Mac on the same Wi-Fi. Find your Mac's LAN IP:

```bash
ipconfig getifaddr en0   # Wi-Fi
# or
ipconfig getifaddr en1   # Ethernet
```

Use that IP (typically `192.168.x.y` or `10.x.y.z`) as the proxy server on the phone, port `8080`. Breaks the moment you change network — most coffee-shop and corporate networks block client-to-client traffic anyway, so prefer Tailscale unless you're at home.

### Option C — ngrok / localtunnel

Tunnel `localhost:8080` to a public URL and point the phone at that. Works in the most hostile networks but adds latency and a third party in the loop. Not covered here.

## Device setup (one-time)

You need the device to (a) route traffic through your Mac (see "Networking" above) and (b) trust the mitmproxy CA.

### iOS

1. Proxy: see "Networking" above.
2. Cert: open `http://mitm.it` in Safari, tap iOS, install the profile.
3. Settings → General → VPN & Device Management → mitmproxy → **Install** → trust.
4. Settings → General → About → Certificate Trust Settings → enable **mitmproxy**.

### Android

1. Proxy: Wi-Fi settings → long-press the network → Modify → Advanced → Manual proxy → host = Mac IP, port = `8080`. (For Tailscale on Android, set the proxy on the Wi-Fi network you're connected to — Tailscale routes the destination IP for you.)
2. Cert: open `http://mitm.it` in Chrome, download the Android cert, install as a **user CA**.
3. From Android 7+, apps only trust user CAs if they opt in via `android:networkSecurityConfig`. Most production apps don't, so you'll need either:
   - a debug build of the app you control, OR
   - a rooted device with the cert installed as a system CA, OR
   - patching the APK (out of scope here).

> Cert pinning will defeat mitmproxy on some apps. The capture script ignores Apple/Google system domains by default — those are the most common pinning offenders. If a specific SDK refuses to talk through the proxy at all, that's usually pinning.

## Usage

### 1. Capture

```bash
./run.sh
```

Then on the phone: open the app, go through the flow you want to audit (cold start → onboarding → purchase / trial / login / deep-link landing). The terminal streams classified traffic in real time. `Ctrl+C` to stop and print a summary.

The full capture is in `/tmp/mitmproxy_capture.json` (atomic writes — survives `kill -9`).

### 2. Report

```bash
python3 generate_report.py --app-name MyApp --platform swift
```

Flags:

- `--app-name` — title for the report (auto-detected from the bundle ID if omitted)
- `--platform` — `swift` (default), `kotlin`, `unity`, or `react-native` — controls the language of the code samples in the recommendations
- `--capture-file` — path to the JSON (default `/tmp/mitmproxy_capture.json`)
- `--output-dir` — where to write the report (default `~/Downloads`)

Outputs:

- `~/Downloads/<app>-sdk-audit-<YYYY-MM-DD>.md`
- `~/Downloads/<app>-sdk-audit-<YYYY-MM-DD>.pdf`

The PDF lists, per SDK: integration status, Advanced Matching, custom events, IDFA, ATT status, deep-link signals — then platform-specific code snippets to fix what's missing.

## Use as a Claude Code skill (optional)

The repo ships a `SKILL.md` that turns the workflow into an auto-triggered [Claude Code](https://claude.com/claude-code) skill. After installation, asking Claude Code things like *"audit sdk de cette app"*, *"lance mitmproxy"*, *"check advanced matching"*, *"what does the app send to Meta"*, etc. will automatically:

1. Launch `run.sh` in the background
2. Wait for you to drive the app on the phone
3. Read `/tmp/mitmproxy_capture.json`, detect the platform, classify each SDK
4. Generate the PDF report in `~/Downloads/`

### Install (one-time)

```bash
git clone git@github.com:firsttrydotco/sdk-audit.git ~/sdk-audit
mkdir -p ~/.claude/skills
ln -s ~/sdk-audit ~/.claude/skills/sdk-audit
```

A symlink (rather than a copy) means `git pull` on the repo immediately updates the skill — no re-install needed.

To verify Claude Code sees the skill, start a new session and run `/help` — `sdk-audit` should appear in the available skills.

### How the skill works

`SKILL.md` describes:

- **Triggers** (frontmatter `description`): the phrases Claude Code matches to invoke the skill.
- **Phase 1 — Capture**: launches `run.sh` in background and asks the user to drive the app.
- **Phase 2 — Analysis**: detection rules per SDK (Meta `ud` field, AppsFlyer `customer_user_id`, Adjust `partner_params`, RevenueCat anonymous vs identified, hidden-SDK fingerprints like `$appsflyerId` in RevenueCat attributes, etc.) and platform-detection signals.
- **Phase 3 — Report**: how to call `generate_report.py` and what the PDF must contain.

Edit `SKILL.md` to add SDKs, change report sections, or tune the trigger phrases — Claude Code re-reads it on every session.

## What gets detected

| Category | SDKs (label) |
|---|---|
| MMPs | Meta (Facebook), Adjust, AppsFlyer, Branch, TikTok, Singular, Kochava, Tenjin |
| Paywall / subs | RevenueCat, Superwall, Adapty, Qonversion, Glassfy, Purchasely |
| Messaging / CRM | Customer.io, Intercom, Braze, OneSignal, Pusher, Leanplum, CleverTap, MoEngage, Iterable |
| Analytics | Amplitude, Mixpanel, Segment, PostHog, Heap, Statsig |
| Firebase / errors | Firebase Analytics, Crashlytics, Sentry, Bugsnag, Datadog |
| A/B & flags | LaunchDarkly, Optimizely, Apptimize, ConfigCat |
| Apple Ad Attribution | app-ads-services |

Unknown hosts are still captured and grouped in the summary, with an `[IDFA]` flag if they leak the advertising ID — useful to spot SDKs not in the table.

## File layout

```
sdk-audit/
├── README.md
├── LICENSE
├── requirements.txt
├── SKILL.md              # Claude Code skill definition (optional install)
├── run.sh                # launcher for mitmdump + capture.py
├── capture.py            # mitmproxy addon: classify, parse, append to JSON
└── generate_report.py    # JSON → Markdown + PDF audit (no font deps)
```

## Notes & limitations

- **Cert pinning**: any app that pins certificates won't talk through the proxy at all. There's no workaround in this repo — use Frida / objection on a jailbroken device if you need to bypass pinning.
- **Encrypted payloads**: some SDKs (recent TikTok, certain Branch endpoints) wrap their JSON in protobuf or custom encryption. They'll still appear in the host counts, but the body parsing is best-effort.
- **iOS-first**: the report wording defaults to Swift and references ATT / IDFA. Android works but you'll usually want `--platform kotlin`.
- **The PDF report is opinionated**: it flags missing Advanced Matching / custom events as `[KO]`, which is correct for performance-marketing apps but may be too strict for apps that intentionally don't track users.

## Contributing

PRs welcome. Common additions:

- new SDK in `classify_host()` (one entry, label, optional source-specific summary in `_print_section`)
- new analyzer in `generate_report.py` (mirror the shape of `analyze_meta` / `analyze_adjust`)
- platform-specific code snippet block in `CODE_EXAMPLES`

## License

MIT — see `LICENSE`.
