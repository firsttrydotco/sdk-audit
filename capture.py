"""mitmproxy addon to capture ALL app traffic and classify post-hoc.

Captures everything — known SDKs are labeled, unknown hosts stored for analysis.
No traffic is dropped (except Apple/Google system domains ignored in run.sh).

Usage: mitmdump -s capture.py
"""
import json
import os
import time
from urllib.parse import parse_qs
from mitmproxy import http

CAPTURE_FILE = "/tmp/mitmproxy_capture.json"
_TMP_FILE = CAPTURE_FILE + ".tmp"
captured = {"meta": [], "adjust": [], "appsflyer": [], "branch": [], "other_mmps": [], "other_sdks": [], "unknown": []}


def _save_json():
    """Atomic write: write to temp file then rename (survives kill -9)."""
    with open(_TMP_FILE, "w") as f:
        json.dump(captured, f, indent=2, default=str)
    os.replace(_TMP_FILE, CAPTURE_FILE)


# --- Host classifiers ---

def classify_host(host):
    """Return (category, label) for a host. Returns ("unknown", host) for unrecognized hosts."""
    # --- MMPs ---
    if any(d in host for d in ["facebook.com", "fbcdn.net", "facebook.net", "fbsbx.com"]):
        return "meta", "META"
    if any(d in host for d in ["adjust.com", "adjust.net", "adjust.world"]):
        return "adjust", "ADJUST"
    if any(d in host for d in ["appsflyer.com", "appsflyersdk.com", "onelink.me", "onelnk.com"]):
        return "appsflyer", "APPSFLYER"
    if any(d in host for d in ["branch.io", "bnc.lt", "app.link"]):
        return "branch", "BRANCH"
    if "tiktok.com" in host:
        return "other_mmps", "TIKTOK"
    if "singular.net" in host:
        return "other_mmps", "SINGULAR"
    if "kochava.com" in host:
        return "other_mmps", "KOCHAVA"
    if "tenjin.com" in host:
        return "other_mmps", "TENJIN"
    # --- Paywall / Subscription SDKs ---
    if "revenuecat.com" in host:
        return "other_sdks", "REVENUECAT"
    if any(d in host for d in ["superwall.me", "superwall.com", "superwallassets.com", "superwalleditor.com"]):
        return "other_sdks", "SUPERWALL"
    if any(d in host for d in ["adapty.io", "adapty.com"]):
        return "other_sdks", "ADAPTY"
    if "qonversion.io" in host:
        return "other_sdks", "QONVERSION"
    if "glassfy.io" in host:
        return "other_sdks", "GLASSFY"
    if "purchasely.io" in host or "purchasely.com" in host:
        return "other_sdks", "PURCHASELY"
    # --- Messaging / CRM SDKs ---
    if "customer.io" in host:
        return "other_sdks", "CUSTOMER.IO"
    if any(d in host for d in ["intercom.com", "intercom.io"]):
        return "other_sdks", "INTERCOM"
    if any(d in host for d in ["braze.com", "appboy.com"]):
        return "other_sdks", "BRAZE"
    if "onesignal.com" in host:
        return "other_sdks", "ONESIGNAL"
    if "pusher.com" in host or "pusherplatform.io" in host:
        return "other_sdks", "PUSHER"
    if "leanplum.com" in host:
        return "other_sdks", "LEANPLUM"
    if any(d in host for d in ["clevertap.com", "clevertap.io"]):
        return "other_sdks", "CLEVERTAP"
    if any(d in host for d in ["moengage.com", "moengage.io"]):
        return "other_sdks", "MOENGAGE"
    if "iterable.com" in host:
        return "other_sdks", "ITERABLE"
    # --- Analytics SDKs ---
    if any(d in host for d in ["amplitude.com", "amplitude.io"]):
        return "other_sdks", "AMPLITUDE"
    if "mixpanel.com" in host:
        return "other_sdks", "MIXPANEL"
    if any(d in host for d in ["segment.io", "segment.com"]):
        return "other_sdks", "SEGMENT"
    if "posthog.com" in host:
        return "other_sdks", "POSTHOG"
    if "heap.io" in host or "heapanalytics.com" in host:
        return "other_sdks", "HEAP"
    if "statsig.com" in host:
        return "other_sdks", "STATSIG"
    # --- Firebase / Crashlytics ---
    if any(d in host for d in ["crashlytics.com", "app-analytics-services", "firebaseinstallations", "firebaseremoteconfig"]):
        return "other_sdks", "FIREBASE"
    # --- Error tracking ---
    if "sentry.io" in host:
        return "other_sdks", "SENTRY"
    if "bugsnag.com" in host:
        return "other_sdks", "BUGSNAG"
    if any(d in host for d in ["datadoghq.com", "datadoghq.eu"]):
        return "other_sdks", "DATADOG"
    # --- A/B testing / Feature flags ---
    if "launchdarkly.com" in host:
        return "other_sdks", "LAUNCHDARKLY"
    if "optimizely.com" in host:
        return "other_sdks", "OPTIMIZELY"
    if "apptimize.com" in host:
        return "other_sdks", "APPTIMIZE"
    # --- Feature flags / Config ---
    if "configcat.com" in host:
        return "other_sdks", "CONFIGCAT"
    # --- App engagement ---
    if any(d in host for d in ["appstack.io", "appstack.com"]):
        return "other_sdks", "APPSTACK"
    # --- Apple Ad Attribution ---
    if "app-ads-services.com" in host:
        return "other_sdks", "APPLE_ADS_ATTRIBUTION"
    # --- CDN / static assets — skip entirely (noise) ---
    if any(d in host for d in ["b-cdn.net", "cloudflare.com", "cloudfront.net", "fastly.net", "akamai"]):
        return None, None
    # --- Unknown host — still captured ---
    return "unknown", host


def _contains_device_id(params: dict, body: dict) -> bool:
    """Check if request contains IDFA, IDFV, or advertising ID."""
    all_text = json.dumps({**params, **body}).lower()
    return any(k in all_text for k in ["idfa", "idfv", "advertising_id", "advertisingid", "gaid", "aaid"])


def parse_body(flow):
    """Parse request body as JSON, form-urlencoded, or raw."""
    if not flow.request.content:
        return {}
    content_type = flow.request.headers.get("content-type", "")
    raw = flow.request.content.decode("utf-8", errors="replace")
    try:
        if "json" in content_type:
            return json.loads(raw)
        elif "form" in content_type or "urlencoded" in content_type:
            d = parse_qs(raw)
            return {k: v[0] if len(v) == 1 else v for k, v in d.items()}
        else:
            try:
                return json.loads(raw)
            except Exception:
                try:
                    d = parse_qs(raw)
                    return {k: v[0] if len(v) == 1 else v for k, v in d.items()}
                except Exception:
                    return {"_raw": raw[:2000]} if raw.strip() else {}
    except Exception:
        return {"_raw": raw[:2000]}


# --- Pretty printers ---

def print_meta(all_data):
    """Print interesting Meta SDK fields."""
    interesting = ["event", "custom_events", "application_tracking_enabled", "advertiser_tracking_enabled",
                   "advertiser_id", "anon_id", "app_user_id", "extinfo", "ud", "sdk_version",
                   "bundle_id", "bundle_short_version", "url_schemes"]
    for key in interesting:
        if key in all_data:
            val = str(all_data[key])
            if len(val) > 300:
                val = val[:300] + "..."
            print(f"  {key}: {val}")
    if "custom_events" in all_data:
        try:
            events = json.loads(all_data["custom_events"]) if isinstance(all_data["custom_events"], str) else all_data["custom_events"]
            print("  >> DECODED custom_events:")
            for ev in events:
                print(f"     event: {ev.get('_eventName', 'unknown')}")
                for k, v in ev.items():
                    if k != "_eventName":
                        print(f"       {k}: {v}")
        except Exception:
            pass


def print_mmp_params(all_data, label):
    """Print all params for an MMP (Adjust, AppsFlyer, Branch, etc.)."""
    # Highlight web-to-app / deep link signals
    web_to_app_keys = [
        "deeplink", "deep_link", "deferred_deeplink", "af_dp", "af_web_dp", "af_force_deeplink",
        "is_retargeting", "retargeting_conversion_type", "af_reengagement_window",
        "onelink", "redirect", "referrer", "install_referrer",
        "link_url", "link", "click_id", "clickid",
        "campaign", "campaign_id", "c", "pid", "media_source", "af_channel",
        "af_adset", "af_ad", "af_sub1", "af_sub2", "af_sub3", "af_sub4", "af_sub5",
    ]
    # Highlight user data / advanced matching signals
    user_data_keys = [
        "customer_user_id", "cuid", "email", "sha1_email", "sha256_email",
        "phone", "sha1_phone", "sha256_phone",
        "ud", "user_data", "partner_params", "callback_params",
    ]

    found_web_to_app = []
    found_user_data = []

    for k, v in sorted(all_data.items()):
        v_str = str(v)
        if len(v_str) > 200:
            v_str = v_str[:200] + "..."

        k_lower = k.lower()
        if any(wk in k_lower for wk in web_to_app_keys):
            found_web_to_app.append(k)
            print(f"  \033[36m[W2A] {k}: {v_str}\033[0m")
        elif any(uk in k_lower for uk in user_data_keys):
            found_user_data.append(k)
            print(f"  \033[33m[UD]  {k}: {v_str}\033[0m")
        else:
            print(f"  {k}: {v_str}")

    if found_web_to_app:
        print(f"  >> Web-to-app signals: {', '.join(found_web_to_app)}")
    if found_user_data:
        print(f"  >> User data fields: {', '.join(found_user_data)}")


def print_appsflyer(all_data):
    """Print AppsFlyer-specific analysis."""
    print_mmp_params(all_data, "APPSFLYER")

    # Check for specific AppsFlyer advanced matching
    af_user_keys = ["customer_user_id", "sha1_email", "sha256_email", "sha1_phone", "sha256_phone", "emails", "phones"]
    found = [k for k in af_user_keys if k in all_data]
    if found:
        print(f"  >> AppsFlyer Advanced Matching ACTIVE: {', '.join(found)}")
    else:
        print(f"  >> AppsFlyer Advanced Matching: NOT detected")


# --- Main request handler ---

def request(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    category, label = classify_host(host)

    method = flow.request.method
    params = dict(flow.request.query) if flow.request.query else {}
    body_data = parse_body(flow)

    # CDN / skipped hosts
    if category is None:
        return

    # For unknown hosts, flag if they contain device IDs (more interesting)
    has_device_id = False
    if category == "unknown":
        has_device_id = _contains_device_id(params, body_data)
        label = f"{'[IDFA] ' if has_device_id else ''}{host}"

    path = flow.request.path
    ts = time.strftime("%H:%M:%S")

    all_data = {**params, **body_data}

    print(f"\n{'=' * 80}")
    print(f"[{ts}] {label} | {method} {host}{path[:120]}")

    if label == "META":
        print_meta(all_data)
    elif label == "APPSFLYER":
        print_appsflyer(all_data)
    elif label in ("ADJUST", "BRANCH", "SINGULAR", "KOCHAVA", "TENJIN"):
        print_mmp_params(all_data, label)
    else:
        # Other SDKs - print events if present
        for key in ["event", "events", "event_name", "action"]:
            if key in all_data:
                print(f"  {key}: {all_data[key]}")

    entry = {"time": ts, "source": label, "method": method, "host": host, "path": path,
             "params": params, "body": body_data}

    captured[category].append(entry)
    _save_json()

    counts = ", ".join(f"{k}={len(v)}" for k, v in captured.items() if v)
    print(f"  [Total: {counts}]")


# --- Summary on Ctrl+C ---

def _print_section(title, entries):
    """Print summary for a category."""
    print(f"\n{'=' * 40}")
    print(f"{title} - {len(entries)} requests")
    print(f"{'=' * 40}")

    if not entries:
        print("  (none)")
        return

    # Endpoints
    endpoints = {}
    for r in entries:
        key = f"{r['method']} {r['host']}{r['path'][:80]}"
        endpoints[key] = endpoints.get(key, 0) + 1
    print("\nEndpoints:")
    for ep, count in sorted(endpoints.items(), key=lambda x: -x[1]):
        print(f"  {ep} (x{count})")

    # Source-specific summaries
    sources = set(r.get("source", "") for r in entries)

    for source in sources:
        source_entries = [r for r in entries if r.get("source") == source]

        if source == "META":
            meta_events = []
            for r in source_entries:
                all_data = {**r.get("params", {}), **r.get("body", {})}
                if "custom_events" in all_data:
                    try:
                        events = json.loads(all_data["custom_events"]) if isinstance(all_data["custom_events"], str) else all_data["custom_events"]
                        meta_events.extend(events)
                    except Exception:
                        pass
            if meta_events:
                print(f"\nCustom Events ({len(meta_events)}):")
                event_names = {}
                for ev in meta_events:
                    name = ev.get("_eventName", "unknown")
                    event_names[name] = event_names.get(name, 0) + 1
                for name, count in sorted(event_names.items(), key=lambda x: -x[1]):
                    print(f"  {name}: x{count}")

        if source in ("ADJUST", "APPSFLYER", "BRANCH", "SINGULAR", "KOCHAVA", "TENJIN"):
            all_params = set()
            event_tokens = set()
            partner_params = {}
            callback_params = {}
            user_data_fields = {}
            web_to_app_fields = {}

            w2a_keys = ["deeplink", "deep_link", "deferred_deeplink", "af_dp", "af_web_dp",
                        "is_retargeting", "retargeting_conversion_type", "onelink", "redirect",
                        "referrer", "install_referrer", "campaign", "media_source", "pid",
                        "af_channel", "af_adset", "af_ad", "c"]
            ud_keys = ["customer_user_id", "cuid", "email", "sha1_email", "sha256_email",
                       "phone", "sha1_phone", "sha256_phone", "emails", "phones"]

            for r in source_entries:
                all_data = {**r.get("params", {}), **r.get("body", {})}
                all_params.update(all_data.keys())
                if "event_token" in all_data:
                    event_tokens.add(all_data["event_token"])
                for k, v in all_data.items():
                    k_lower = k.lower()
                    if k.startswith("partner_params") or k.startswith("callback_params"):
                        (partner_params if "partner" in k else callback_params)[k] = v
                    if any(uk in k_lower for uk in ud_keys):
                        user_data_fields[k] = str(v)[:100]
                    if any(wk in k_lower for wk in w2a_keys):
                        web_to_app_fields[k] = str(v)[:100]

            if event_tokens:
                print(f"\nEvent tokens: {', '.join(sorted(event_tokens))}")
            if partner_params:
                print(f"\nPartner params: {json.dumps(partner_params, indent=2)}")
            if callback_params:
                print(f"\nCallback params: {json.dumps(callback_params, indent=2)}")
            if user_data_fields:
                print(f"\n** User data / Advanced Matching:")
                for k, v in user_data_fields.items():
                    print(f"  {k}: {v}")
            else:
                print(f"\n** No user data / Advanced Matching detected")
            if web_to_app_fields:
                print(f"\n** Web-to-app / Deep link signals:")
                for k, v in web_to_app_fields.items():
                    print(f"  {k}: {v}")
            if all_params:
                print(f"\nAll params seen: {', '.join(sorted(all_params))}")


def done():
    """Print summary when mitmdump stops (Ctrl+C)."""
    print(f"\n\n{'=' * 80}")
    print("CAPTURE SUMMARY")
    print("=" * 80)

    _print_section("META ADS", captured["meta"])
    _print_section("ADJUST", captured["adjust"])
    _print_section("APPSFLYER", captured["appsflyer"])
    _print_section("BRANCH", captured["branch"])
    _print_section("OTHER MMPs (TikTok/Singular/Kochava/Tenjin)", captured["other_mmps"])

    # Other SDKs - simple host count
    print(f"\n{'=' * 40}")
    print(f"OTHER SDKs - {len(captured['other_sdks'])} requests")
    print(f"{'=' * 40}")
    sdk_hosts = {}
    for r in captured["other_sdks"]:
        label = r.get("source", r["host"])
        sdk_hosts[label] = sdk_hosts.get(label, 0) + 1
    for host, count in sorted(sdk_hosts.items(), key=lambda x: -x[1]):
        print(f"  {host}: x{count}")

    # Unknown hosts — grouped by domain
    print(f"\n{'=' * 40}")
    print(f"UNKNOWN HOSTS - {len(captured['unknown'])} requests")
    print(f"{'=' * 40}")
    if captured["unknown"]:
        unknown_hosts = {}
        idfa_hosts = set()
        for r in captured["unknown"]:
            h = r.get("host", "?")
            unknown_hosts[h] = unknown_hosts.get(h, 0) + 1
            if "[IDFA]" in r.get("source", ""):
                idfa_hosts.add(h)
        for h, count in sorted(unknown_hosts.items(), key=lambda x: -x[1]):
            idfa_flag = " [IDFA]" if h in idfa_hosts else ""
            print(f"  {h}: x{count}{idfa_flag}")
    else:
        print("  (none)")

    _save_json()
    print(f"\nFull capture saved to {CAPTURE_FILE}")
