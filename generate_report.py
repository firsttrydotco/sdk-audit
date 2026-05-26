#!/usr/bin/env python3
"""Generate SDK audit report (Markdown + PDF) from mitmproxy capture.

Usage:
    python3 generate_report.py [--app-name NAME] [--platform unity|swift|kotlin|react-native]

Reads /tmp/mitmproxy_capture.json and outputs to ~/Downloads/:
    - {app_name}-sdk-audit-{date}.md
    - {app_name}-sdk-audit-{date}.pdf
"""
import argparse
import json
import os
import re
import sys
from datetime import date

CAPTURE_FILE = "/tmp/mitmproxy_capture.json"
OUTPUT_DIR = os.path.expanduser("~/Downloads")

# --- Analysis helpers ---

def analyze_meta(entries: list) -> dict:
    """Analyze Meta SDK requests."""
    result = {
        "present": len(entries) > 0,
        "request_count": len(entries),
        "sdk_version": None,
        "advanced_matching": False,
        "ud_content": {},
        "custom_events": [],
        "auto_events_only": True,
        "att_enabled": None,
        "idfa": None,
        "bundle_id": None,
        "app_version": None,
    }
    auto_events = {
        "fb_mobile_activate_app", "fb_mobile_deactivate_app", "fb_sdk_initialize",
        "fb_sdk_background_status_available", "fb_mobile_ate_status",
    }
    for r in entries:
        all_data = {**r.get("params", {}), **r.get("body", {})}

        # SDK version from batch requests
        if "sdk_version" in all_data:
            result["sdk_version"] = all_data["sdk_version"]
        # Try extracting from batch URL
        if "batch" in all_data:
            raw = str(all_data["batch"])
            if "sdk_version=" in raw:
                m = re.search(r"sdk_version=([0-9.]+)", raw)
                if m:
                    result["sdk_version"] = m.group(1)

        # Advanced Matching
        if "ud" in all_data:
            try:
                ud = json.loads(all_data["ud"]) if isinstance(all_data["ud"], str) else all_data["ud"]
                if ud and ud != {}:
                    result["advanced_matching"] = True
                    result["ud_content"] = ud
            except (json.JSONDecodeError, TypeError):
                pass

        # Custom events
        if "custom_events" in all_data:
            try:
                events = json.loads(all_data["custom_events"]) if isinstance(all_data["custom_events"], str) else all_data["custom_events"]
                for ev in events:
                    name = ev.get("_eventName", "unknown")
                    result["custom_events"].append({"name": name, "params": {k: v for k, v in ev.items() if k != "_eventName"}})
                    if name not in auto_events:
                        result["auto_events_only"] = False
            except (json.JSONDecodeError, TypeError):
                pass

        # ATT
        if "advertiser_tracking_enabled" in all_data:
            result["att_enabled"] = all_data["advertiser_tracking_enabled"] == "1"
        if "advertiser_id" in all_data:
            result["idfa"] = all_data["advertiser_id"]

        # App info from extinfo
        if "extinfo" in all_data:
            try:
                info = json.loads(all_data["extinfo"]) if isinstance(all_data["extinfo"], str) else all_data["extinfo"]
                if isinstance(info, list) and len(info) > 1:
                    result["bundle_id"] = info[1]
                if isinstance(info, list) and len(info) > 3:
                    result["app_version"] = info[3]
            except (json.JSONDecodeError, TypeError):
                pass

    event_names = [e["name"] for e in result["custom_events"]]
    result["event_names"] = list(set(event_names))
    return result


def analyze_adjust(entries: list) -> dict:
    """Analyze Adjust SDK requests."""
    result = {
        "present": len(entries) > 0,
        "request_count": len(entries),
        "sdk_version": None,
        "app_token": None,
        "partner_params": {},
        "callback_params": {},
        "event_tokens": set(),
        "has_custom_events": False,
        "idfa": None,
        "att_status": None,
        "fb_anon_id": None,
        "skan_configured": False,
        "all_params": set(),
    }
    for r in entries:
        all_data = {**r.get("params", {}), **r.get("body", {})}
        result["all_params"].update(all_data.keys())

        if "app_token" in all_data:
            result["app_token"] = all_data["app_token"]
        # Adjust SDK version: param like "ios5.0.0" / "android4.38.0"
        if not result["sdk_version"]:
            sdk_v = all_data.get("sdk_version") or all_data.get("sdk")
            if sdk_v:
                result["sdk_version"] = str(sdk_v)
        if "idfa" in all_data:
            result["idfa"] = all_data["idfa"]
        if "att_status" in all_data:
            result["att_status"] = all_data["att_status"]
        if "fb_anon_id" in all_data:
            result["fb_anon_id"] = all_data["fb_anon_id"]
        if "last_skan_update" in all_data:
            result["skan_configured"] = True
        if "event_token" in all_data:
            result["event_tokens"].add(all_data["event_token"])
            result["has_custom_events"] = True

        for k, v in all_data.items():
            if k.startswith("partner_params"):
                result["partner_params"][k] = v
            if k.startswith("callback_params"):
                result["callback_params"][k] = v

    result["event_tokens"] = list(result["event_tokens"])
    result["all_params"] = sorted(result["all_params"])
    return result


def analyze_appsflyer(entries: list) -> dict:
    """Analyze AppsFlyer SDK requests."""
    result = {
        "present": len(entries) > 0,
        "request_count": len(entries),
        "sdk_version": None,
        "dev_key": None,
        "app_id": None,
        "advanced_matching": False,
        "user_data_fields": [],
        "custom_events": [],
        "has_custom_events": False,
        "idfa": None,
        "att_status": None,
        "customer_user_id": None,
        "web_to_app_signals": {},
        "all_params": set(),
    }
    user_data_keys = {"customer_user_id", "cuid", "sha1_email", "sha256_email",
                      "sha1_phone", "sha256_phone", "emails", "phones", "email"}
    w2a_keys = {"af_dp", "af_web_dp", "af_force_deeplink", "is_retargeting",
                "retargeting_conversion_type", "af_reengagement_window",
                "deeplink", "deep_link_value", "deep_link_sub1",
                "campaign", "media_source", "pid", "af_channel",
                "af_adset", "af_ad", "af_sub1", "af_sub2", "af_sub3", "af_sub4", "af_sub5",
                "install_referrer", "referrer"}

    for r in entries:
        all_data = {**r.get("params", {}), **r.get("body", {})}
        result["all_params"].update(all_data.keys())

        # SDK version: af_v / sdkVersion / sdk_version
        if not result["sdk_version"]:
            v = all_data.get("af_v") or all_data.get("sdkVersion") or all_data.get("sdk_version")
            if v:
                result["sdk_version"] = str(v)

        # Dev key / app ID
        if "devkey" in all_data or "af_devkey" in all_data:
            result["dev_key"] = all_data.get("devkey", all_data.get("af_devkey"))
        if "app_id" in all_data:
            result["app_id"] = all_data["app_id"]

        # IDFA / ATT
        if "idfa" in all_data:
            result["idfa"] = all_data["idfa"]
        if "att" in all_data or "att_status" in all_data:
            result["att_status"] = all_data.get("att", all_data.get("att_status"))

        # Customer user ID
        if "customer_user_id" in all_data or "cuid" in all_data:
            result["customer_user_id"] = all_data.get("customer_user_id", all_data.get("cuid"))

        # User data / advanced matching
        for k in all_data:
            if k.lower() in user_data_keys:
                result["advanced_matching"] = True
                result["user_data_fields"].append(k)

        # Web-to-app / deep link signals
        for k, v in all_data.items():
            if k.lower() in w2a_keys:
                result["web_to_app_signals"][k] = str(v)[:200]

        # Events (AppsFlyer sends events via POST with event_name)
        event_name = all_data.get("event_name", all_data.get("eventName", all_data.get("af_events_api")))
        if event_name and event_name not in ("session", "install"):
            result["custom_events"].append(event_name)
            result["has_custom_events"] = True

        # Check path for launch/event endpoints
        path = r.get("path", "")
        if "/inappevent/" in path or "/api/v" in path:
            result["has_custom_events"] = True

    result["user_data_fields"] = list(set(result["user_data_fields"]))
    result["custom_events"] = list(set(result["custom_events"]))
    result["all_params"] = sorted(result["all_params"])
    return result


def analyze_branch(entries: list) -> dict:
    """Analyze Branch SDK requests."""
    result = {
        "present": len(entries) > 0,
        "request_count": len(entries),
        "sdk_version": None,
        "branch_key": None,
        "identity_set": False,
        "deep_link_detected": False,
        "events": [],
        "all_params": set(),
    }
    for r in entries:
        all_data = {**r.get("params", {}), **r.get("body", {})}
        result["all_params"].update(all_data.keys())

        if "branch_key" in all_data:
            result["branch_key"] = all_data["branch_key"]
        if not result["sdk_version"]:
            v = all_data.get("sdk") or all_data.get("sdk_version")
            if v:
                result["sdk_version"] = str(v)
        if "identity" in all_data or "developer_identity" in all_data:
            result["identity_set"] = True

        path = r.get("path", "")
        if "/open" in path or "/install" in path:
            result["deep_link_detected"] = True
        if "event" in all_data:
            result["events"].append(all_data["event"])

    result["events"] = list(set(result["events"]))
    result["all_params"] = sorted(result["all_params"])
    return result


def analyze_other_mmps(entries: list) -> dict:
    """Analyze other MMP requests (Singular, Kochava, Tenjin)."""
    mmps = {}
    for r in entries:
        source = r.get("source", r["host"])
        if source not in mmps:
            mmps[source] = {"count": 0, "events": [], "params": set()}
        mmps[source]["count"] += 1
        all_data = {**r.get("params", {}), **r.get("body", {})}
        mmps[source]["params"].update(all_data.keys())
        for k in ["event", "event_name", "event_token"]:
            if k in all_data:
                mmps[source]["events"].append(all_data[k])
    for m in mmps.values():
        m["events"] = list(set(m["events"]))
        m["params"] = sorted(m["params"])
    return mmps


# Hosts that are pure fingerprinting / fraud telemetry, not actual charges.
# Matched with exact or suffix comparison so e.g. "xm.stripe.com" does not
# accidentally get skipped as fingerprinting (would hide a real charge).
#
# NOTE: paypalobjects.com is currently UNREACHABLE here because capture.py
# intentionally does not classify it as payment. It is kept in this list as
# a forward-defence guard in case a future commit re-adds PayPal's CDN to
# the classifier — the fingerprint exclusion would then immediately prevent
# false-positive charge attempts without needing a separate fix.
FINGERPRINT_HOSTS = ("m.stripe.com", "m.stripe.network", "r.stripe.com", "q.stripe.com",
                     "js.stripe.com", "paypalobjects.com", "b.stripecdn.com")


def _is_fingerprint_host(h):
    return any(h == fh or h.endswith("." + fh) for fh in FINGERPRINT_HOSTS)


def analyze_paywall_compliance(payment_entries: list, other_sdks_entries: list) -> dict:
    """Audit Apple App Store Guideline 3.1.1 / IAP bypass signals.

    Looks for payment processor calls and correlates them with the paywall
    SDK (Superwall, RevenueCat, Adapty) present in other_sdks. Extracts
    Superwall variant/experiment info and product identifiers to document
    which cohort this session audited.

    Verdict logic:
      - HIGH_RISK: actual payment_intents/setup_intents POST to a processor
      - REVIEW   : payment processor infra loaded (e.g. Stripe.js) but no
                   charge attempt observed — may trigger for other cohorts
      - OK       : no payment processor traffic AND StoreKit confirmed via
                   paywall SDK events
    """
    result = {
        "has_payment_traffic": len(payment_entries) > 0,
        "has_charge_attempt": False,
        "charge_attempts": [],
        "processors": {},
        "paywall_sdk": None,
        "superwall_variants": [],
        "superwall_products": [],
        "paywall_identifier": None,
        "storekit_version": None,
        "store": None,
        "transaction_events": [],
        "verdict": "OK",
        "risk_reasons": [],
        "mmp_attribution_forwarded": {},
    }

    # --- Payment processor inspection ---
    # Per-processor charge endpoints. The Stripe set is well-known; others are
    # listed as observed in the wild. Falls back to a generic POST-to-API-host
    # heuristic for processors where we haven't catalogued the path yet.
    charge_paths_by_processor = {
        "STRIPE": ["/v1/payment_intents", "/v1/setup_intents", "/v1/charges",
                   "/v1/subscriptions", "/v1/invoices", "/v1/orders",
                   "/checkout/sessions"],
        "PADDLE": ["/api/2.0/subscription/", "/api/2.0/payment/", "/checkout/"],
        "LEMONSQUEEZY": ["/v1/checkouts", "/v1/subscriptions", "/v1/orders"],
        "BRAINTREE": ["/client_api/v1/payment_methods", "/merchants/"],
        "ADYEN": ["/checkout/v", "/payments"],
        "PAYPAL": ["/v2/checkout/orders", "/v1/payments", "/v1/billing/subscriptions"],
        "CHECKOUT.COM": ["/payments", "/tokens"],
        "MOLLIE": ["/v2/payments", "/v2/orders"],
        "CHARGEBEE": ["/hosted_pages", "/subscriptions", "/customers"],
        "RECURLY": ["/subscriptions", "/accounts", "/purchases"],
        "RAZORPAY": ["/v1/orders", "/v1/payments", "/v1/subscriptions"],
        "SQUARE": ["/v2/payments", "/v2/checkout", "/v2/online-checkout"],
    }

    # Keywords that strongly suggest a path is a real charge/subscription op,
    # used to tighten the heuristic fallback so an SDK-internal analytics POST
    # to api.<proc>.com isn't flagged as a charge attempt.
    charge_keywords = ("payment", "checkout", "subscription", "order", "charge",
                       "purchase", "billing")

    for r in payment_entries:
        src = r.get("source", "UNKNOWN")
        path = r.get("path", "")
        host = r.get("host", "")
        p = result["processors"].setdefault(src, {"count": 0, "hosts": set(), "paths": set()})
        p["count"] += 1
        p["hosts"].add(host)
        p["paths"].add(path[:80])

        if r.get("method") != "POST":
            continue
        if _is_fingerprint_host(host):
            # Fingerprinting / fraud telemetry — not a charge.
            continue

        known_paths = charge_paths_by_processor.get(src, [])
        is_known_charge = any(cp in path for cp in known_paths)
        # Fallback: a POST to an API host (api.*) for an unknown processor
        # where the path mentions a charge-related keyword. Requiring the
        # keyword avoids flagging SDK analytics POSTs as charges.
        #
        # KNOWN LIMITATION: the `not known_paths` gate means this heuristic
        # only fires for processors that have no catalogued charge paths. If
        # a known processor (e.g. STRIPE) hits an uncatalogued path like
        # /v1/invoices with a charge keyword, it stays silently at REVIEW.
        # That is intentional today to avoid double-counting, but means the
        # per-processor charge_paths list must stay up to date. Add new
        # endpoints there instead of relying on the heuristic.
        looks_like_api = host.startswith("api.") or host.startswith("checkout.")
        path_lower = path.lower()
        has_charge_keyword = any(kw in path_lower for kw in charge_keywords)

        if is_known_charge or (looks_like_api and not known_paths and has_charge_keyword):
            result["has_charge_attempt"] = True
            result["charge_attempts"].append({
                "time": r.get("time"),
                "processor": src,
                "host": host,
                "path": path[:120],
                "confidence": "high" if is_known_charge else "heuristic",
            })
    for p in result["processors"].values():
        p["hosts"] = sorted(p["hosts"])
        p["paths"] = sorted(p["paths"])

    # --- Paywall SDK detection + Superwall event parsing ---
    # NOTE: if an app uses multiple paywall SDKs simultaneously (e.g.
    # RevenueCat + Superwall during an A/B migration), only the first
    # match wins. Switch to a list if that turns out to matter in practice.
    sdk_priority = ["SUPERWALL", "REVENUECAT", "ADAPTY", "QONVERSION", "GLASSFY", "PURCHASELY"]
    seen_sdks = {r.get("source") for r in other_sdks_entries}
    for s in sdk_priority:
        if s in seen_sdks:
            result["paywall_sdk"] = s
            break

    # Parse Superwall events for paywall/product/experiment data. Defensive
    # against bodies where the backend serializes `"events": null` — which
    # would raise TypeError on iteration.
    sw_events = []
    for r in other_sdks_entries:
        if r.get("source") != "SUPERWALL":
            continue
        body = r.get("body", {})
        if not isinstance(body, dict):
            continue
        events = body.get("events")
        if not isinstance(events, list):
            continue
        sw_events.extend(events)

    seen_variants = set()
    for ev in sw_events:
        name = ev.get("event_name", "")
        params = ev.get("parameters", {})
        vid = params.get("$variant_id") or params.get("variant_id")
        eid = params.get("$experiment_id") or params.get("experiment_id")
        pid_ident = params.get("$paywall_identifier") or params.get("paywall_identifier")
        if vid and (vid, eid) not in seen_variants:
            seen_variants.add((vid, eid))
            result["superwall_variants"].append({
                "variant_id": vid, "experiment_id": eid, "paywall_identifier": pid_ident,
            })
        if pid_ident and not result["paywall_identifier"]:
            result["paywall_identifier"] = pid_ident
        skv = params.get("$storekit_version") or params.get("$storeKitVersion")
        if skv:
            result["storekit_version"] = skv
        store = params.get("$store")
        if store:
            result["store"] = store

        if "transaction" in name or name in ("paywall_open", "transaction_start", "transaction_abandon", "transaction_complete"):
            prod_id = params.get("$product_id") or params.get("$primary_product_id")
            if prod_id:
                existing = next((p for p in result["superwall_products"] if p["product_id"] == prod_id), None)
                new_fields = {
                    "price": params.get("$product_price"),
                    "currency": params.get("$product_currency_code"),
                    "period": params.get("$product_period"),
                    "trial_days": params.get("$product_trial_period_days"),
                    "store": params.get("$store"),
                }
                if existing is None:
                    result["superwall_products"].append({"product_id": prod_id, **new_fields})
                else:
                    for k, v in new_fields.items():
                        if v is not None and existing.get(k) is None:
                            existing[k] = v
            result["transaction_events"].append({
                "event": name,
                "time": ev.get("created_at", "")[:19],
                "product_id": prod_id,
                "store": params.get("$store"),
            })

        # MMP attribution forwarded to Superwall. Superwall commonly sends
        # these via setUserAttributes — which shows up as a `user_attributes`
        # event where the attribute keys live at the top level of parameters,
        # not nested. So the same params dict works, but we check both bare
        # and `af_` / `$` prefixed variants.
        mmp_keys = [
            "media_source", "campaign", "campaign_id", "af_ad", "af_adset",
            "af_channel", "click_id", "clickid", "attribution",
            "$media_source", "$campaign",
        ]
        for mmp_key in mmp_keys:
            if mmp_key in params and params[mmp_key]:
                result["mmp_attribution_forwarded"][mmp_key.lstrip("$")] = str(params[mmp_key])[:80]
        # Also scan top-level event body for attributes that Superwall's
        # identify API may include outside the `parameters` object.
        for k in ("attributes", "user_attributes"):
            extra = ev.get(k)
            if isinstance(extra, dict):
                for mmp_key in mmp_keys:
                    if mmp_key in extra and extra[mmp_key]:
                        result["mmp_attribution_forwarded"][mmp_key.lstrip("$")] = str(extra[mmp_key])[:80]

    # --- Verdict ---
    reasons = []
    if result["has_charge_attempt"]:
        result["verdict"] = "HIGH_RISK"
        reasons.append("Direct payment_intents/setup_intents POST to external processor (bypasses StoreKit).")
    elif result["has_payment_traffic"]:
        result["verdict"] = "REVIEW"
        procs = ", ".join(result["processors"].keys())
        reasons.append(f"Payment processor infra loaded ({procs}) without observed charge. "
                       "Other cohorts may see active checkout.")
        if result["paywall_sdk"] == "SUPERWALL" and result["superwall_variants"]:
            reasons.append("Superwall assigned a specific variant for this session; "
                           "other variants may route to the external processor.")
    else:
        if result["store"] == "APP_STORE" and result["storekit_version"]:
            reasons.append(f"StoreKit confirmed ({result['storekit_version']}), no external payment traffic.")
        else:
            reasons.append("No payment processor traffic detected during this session.")

    # Suspicious paywall identifier names
    if result["paywall_identifier"]:
        lower = result["paywall_identifier"].lower()
        if any(s in lower for s in ["appreview", "app-review", "apple-review", "review-safe"]):
            if result["verdict"] == "OK":
                result["verdict"] = "REVIEW"
            reasons.append(f"Paywall identifier '{result['paywall_identifier']}' suggests a "
                           f"variant specifically shown to App Review — other cohorts likely differ.")

    result["risk_reasons"] = reasons
    return result


def _extract_other_sdk_version(name: str, r: dict) -> str | None:
    """Best-effort SDK version extraction from headers / user-agent / params."""
    headers = {k.lower(): v for k, v in r.get("request_headers", {}).items()}
    ua = headers.get("user-agent", "")
    params = r.get("params", {})
    body = r.get("body", {}) if isinstance(r.get("body", {}), dict) else {}

    if name == "RevenueCat":
        # Native SDK sends its version in x-version
        return headers.get("x-version")
    if name == "Crashlytics":
        # user-agent: com.google.firebase.crashlytics.ios/12.3.0
        m = re.search(r"crashlytics\.(?:ios|android)/([\d.]+)", ua)
        return m.group(1) if m else None
    if name == "Firebase Analytics":
        # gmp_version=120300 -> 12.3.0
        gmp = params.get("gmp_version") or body.get("gmp_version")
        if gmp and gmp.isdigit() and len(gmp) >= 5:
            return f"{int(gmp[:-4])}.{int(gmp[-4:-2])}.{int(gmp[-2:])}"
        return None
    if name == "Intercom":
        # Body includes device_data.app_id and sdk version fields; intercom
        # also exposes "X-Intercom-Version" sometimes.
        v = headers.get("x-intercom-version")
        if v:
            return v
        dd = body.get("device_data") if isinstance(body, dict) else None
        if isinstance(dd, dict):
            return dd.get("sdk_version") or dd.get("intercom_sdk_version")
        return None
    if name == "Customer.io":
        return headers.get("x-customerio-cdp-version") or headers.get("user-agent-sdk-version")
    return None


def analyze_other(entries: list) -> dict:
    """Analyze other SDK requests."""
    sdks = {}
    for r in entries:
        host = r["host"]
        source = r.get("source", "")
        if "revenuecat" in host or source == "REVENUECAT":
            name = "RevenueCat"
            is_anonymous = "$RCAnonymousID" in r.get("path", "")
        elif "customer.io" in host or source == "CUSTOMER.IO":
            name = "Customer.io"
            is_anonymous = False
        elif "intercom" in host or source == "INTERCOM":
            name = "Intercom"
            is_anonymous = False
        elif "crashlytics" in host:
            name = "Crashlytics"
            is_anonymous = False
        elif "app-analytics-services" in host or "firebaseinstallations" in host or "firebaseremoteconfig" in host or source == "FIREBASE":
            name = "Firebase Analytics"
            is_anonymous = False
        else:
            name = host
            is_anonymous = False

        if name not in sdks:
            sdks[name] = {"count": 0, "anonymous": False, "version": None}
        sdks[name]["count"] += 1
        if is_anonymous:
            sdks[name]["anonymous"] = True
        if not sdks[name]["version"]:
            v = _extract_other_sdk_version(name, r)
            if v:
                sdks[name]["version"] = v

    return sdks


# --- Legal basis text (shared by markdown and PDF generators) ---

LEGAL_PARA_1 = (
    "This analysis was performed solely by inspecting network traffic emitted by a copy of the "
    "{app_name} application installed on a device owned by the author, over an internet connection "
    "owned by the author. No application code was modified, no third-party infrastructure was "
    "accessed, and no user data other than the author's own test account was collected."
)

LEGAL_PARA_2 = (
    "Inspecting outbound network traffic from one\u2019s own device is not restricted under EU or French "
    "law. No offence under the French Code p\u00e9nal (Art. 323-1 et seq., STAD) or under EU Directive "
    "2013/40/EU on attacks against information systems arises, as no third-party system was accessed. "
    "As a data subject under the GDPR (Art. 15 right of access, Art. 5(1)(a) transparency principle), "
    "the author has a right to understand what personal data is transmitted from their device. No "
    "reverse engineering of the application\u2019s binaries was performed (Directive 2009/24/EC); the "
    "capture relied solely on standard TLS MITM with a user-installed root certificate."
)

LEGAL_PARA_3 = (
    "This report is shared in good faith to help improve the tracking implementation and is not a "
    "public disclosure."
)


# --- Code examples by platform ---

CODE_EXAMPLES = {
    "unity": {
        "meta_advanced_matching": """using Facebook.Unity;

// After login or when email is available
FB.Mobile.SetUserData(
    new Dictionary<string, string>() {
        { "em", user.Email },        // email - SDK hashes automatically
        { "fn", user.FirstName },    // first name (optional)
        { "ln", user.LastName },     // last name (optional)
        { "ph", user.Phone },        // +33... (optional)
        { "ct", user.City },         // city (optional)
        { "zp", user.Zip },          // zip code (optional)
        { "country", user.Country }  // ISO 2-letter (optional)
    }
);""",
        "meta_events": """using Facebook.Unity;

// Purchase / subscription
var purchaseParams = new Dictionary<string, object>() {
    { AppEventParameterName.ContentID, planId },
    { AppEventParameterName.Currency, "EUR" }
};
FB.LogPurchase(price, "EUR", purchaseParams);

// Free trial start
var trialParams = new Dictionary<string, object>() {
    { AppEventParameterName.ContentID, planId },
    { AppEventParameterName.Currency, "EUR" },
    { "fb_content_type", "subscription" }
};
FB.LogAppEvent(AppEventName.StartTrial, price, trialParams);

// Registration
var regParams = new Dictionary<string, object>() {
    { AppEventParameterName.RegistrationMethod, "email" }
};
FB.LogAppEvent(AppEventName.CompletedRegistration, null, regParams);""",
        "adjust_partner_params": """using com.adjust.sdk;

// After login
Adjust.addSessionPartnerParameter("user_id", user.Id);

// Advanced Matching via Adjust:
string hashedEmail = Sha256(user.Email.ToLower());
Adjust.addSessionPartnerParameter("em", hashedEmail);""",
        "adjust_events": """using com.adjust.sdk;

// Subscription
AdjustEvent adjustEvent = new AdjustEvent("EVENT_TOKEN");
adjustEvent.setRevenue(price, "EUR");
adjustEvent.setTransactionId(transactionId);
Adjust.trackEvent(adjustEvent);

// Trial start
AdjustEvent trialEvent = new AdjustEvent("TRIAL_TOKEN");
Adjust.trackEvent(trialEvent);""",
        "revenuecat_login": """using RevenueCat.Unity;

var purchases = GetComponent<Purchases>();
purchases.LogIn(user.Id, (customerInfo, created, error) => {
    // User identified in RevenueCat
});""",
    },
    "swift": {
        "meta_advanced_matching": """import FBSDKCoreKit

// After login or when email is available
AppEvents.shared.setUserData(
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    phone: user.phone,       // international format +33...
    dateOfBirth: user.dob,   // format YYYYMMDD
    gender: user.gender,     // "m" or "f"
    city: user.city,
    state: nil,
    zip: user.zip,
    country: user.country    // ISO 2-letter code
)""",
        "meta_events": """import FBSDKCoreKit

// Purchase
AppEvents.shared.logPurchase(amount: price, currency: "EUR")

// Free trial start
AppEvents.shared.logEvent(.startTrial, parameters: [
    .init("fb_content_id"): plan_id,
    .init("fb_currency"): "EUR",
    .init("_valueToSum"): price
])

// Registration
AppEvents.shared.logEvent(.completedRegistration, parameters: [
    .init("fb_registration_method"): "email"
])""",
        "adjust_partner_params": """import Adjust

// After login
Adjust.addSessionPartnerParameter("user_id", value: user.id)

// Advanced Matching via Adjust:
let hashedEmail = user.email.lowercased().sha256()
Adjust.addSessionPartnerParameter("em", value: hashedEmail)""",
        "adjust_events": """import Adjust

// Subscription
let event = ADJEvent(eventToken: "EVENT_TOKEN")
event?.setRevenue(price, currency: "EUR")
event?.setCallbackId(transactionId)
Adjust.trackEvent(event)

// Trial start
let trialEvent = ADJEvent(eventToken: "TRIAL_TOKEN")
Adjust.trackEvent(trialEvent)""",
        "revenuecat_login": """import RevenueCat

Purchases.shared.logIn(user.id) { customerInfo, created, error in
    // User identified in RevenueCat
}""",
    },
    "kotlin": {
        "meta_advanced_matching": """import com.facebook.appevents.AppEventsLogger
import com.facebook.appevents.UserDataStore

// After login
val bundle = Bundle().apply {
    putString("em", user.email)
    putString("fn", user.firstName)
    putString("ln", user.lastName)
    putString("ph", user.phone)
    putString("ct", user.city)
    putString("zp", user.zip)
    putString("country", user.country)
}
AppEventsLogger.setUserData(bundle)""",
        "meta_events": """import com.facebook.appevents.AppEventsLogger

val logger = AppEventsLogger.newLogger(context)

// Purchase
logger.logPurchase(price.toBigDecimal(), Currency.getInstance("EUR"))

// Free trial start
val trialParams = Bundle().apply {
    putString(AppEventsConstants.EVENT_PARAM_CONTENT_ID, planId)
    putString(AppEventsConstants.EVENT_PARAM_CURRENCY, "EUR")
}
logger.logEvent(AppEventsConstants.EVENT_NAME_START_TRIAL, price, trialParams)

// Registration
val regParams = Bundle().apply {
    putString(AppEventsConstants.EVENT_PARAM_REGISTRATION_METHOD, "email")
}
logger.logEvent(AppEventsConstants.EVENT_NAME_COMPLETED_REGISTRATION, regParams)""",
        "adjust_partner_params": """import com.adjust.sdk.Adjust

// After login
Adjust.addSessionPartnerParameter("user_id", user.id)

// Advanced Matching via Adjust:
val hashedEmail = sha256(user.email.lowercase())
Adjust.addSessionPartnerParameter("em", hashedEmail)""",
        "adjust_events": """import com.adjust.sdk.AdjustEvent
import com.adjust.sdk.Adjust

// Subscription
val event = AdjustEvent("EVENT_TOKEN")
event.setRevenue(price, "EUR")
event.setOrderId(transactionId)
Adjust.trackEvent(event)

// Trial start
val trialEvent = AdjustEvent("TRIAL_TOKEN")
Adjust.trackEvent(trialEvent)""",
        "revenuecat_login": """import com.revenuecat.purchases.Purchases

Purchases.sharedInstance.logIn(user.id) { customerInfo, created, error ->
    // User identified in RevenueCat
}""",
    },
}
CODE_EXAMPLES["react-native"] = {
    "meta_advanced_matching": """import { AppEventsLogger } from 'react-native-fbsdk-next';

// After login or when email is available
AppEventsLogger.setUserData({
  email: user.email,          // SDK hashes automatically
  firstName: user.firstName,  // optional
  lastName: user.lastName,    // optional
  phone: user.phone,          // +33... optional
  city: user.city,            // optional
  zip: user.zip,              // optional
  country: user.country,      // ISO 2-letter, optional
});""",
    "meta_events": """import { AppEventsLogger } from 'react-native-fbsdk-next';

// Purchase / subscription
AppEventsLogger.logPurchase(price, 'EUR', {
  fb_content_id: planId,
});

// Free trial start
AppEventsLogger.logEvent('fb_mobile_start_trial', price, {
  fb_content_id: planId,
  fb_currency: 'EUR',
  fb_content_type: 'subscription',
});

// Registration
AppEventsLogger.logEvent('fb_mobile_complete_registration', null, {
  fb_registration_method: 'email',
});""",
    "adjust_partner_params": """import { Adjust } from 'react-native-adjust';

// After login
Adjust.addSessionPartnerParameter('user_id', user.id);

// Advanced Matching via Adjust:
import { sha256 } from 'some-hash-lib';
Adjust.addSessionPartnerParameter('em', sha256(user.email.toLowerCase()));""",
    "adjust_events": """import { Adjust, AdjustEvent } from 'react-native-adjust';

// Subscription
const event = new AdjustEvent('EVENT_TOKEN');
event.setRevenue(price, 'EUR');
event.setTransactionId(transactionId);
Adjust.trackEvent(event);

// Trial start
const trialEvent = new AdjustEvent('TRIAL_TOKEN');
Adjust.trackEvent(trialEvent);""",
    "revenuecat_login": """import Purchases from 'react-native-purchases';

// After login
const { customerInfo, created } = await Purchases.logIn(user.id);""",
}


# --- Markdown report ---

def generate_markdown(meta: dict, adjust: dict, others: dict, app_name: str, platform: str,
                      appsflyer: dict = None, branch: dict = None, other_mmps: dict = None,
                      paywall: dict = None) -> str:
    code = CODE_EXAMPLES.get(platform, CODE_EXAMPLES["unity"])
    lines = []
    a = lines.append

    a(f"# SDK Audit — {app_name}")
    a(f"")
    a(f"**Date:** {date.today().isoformat()}")
    a(f"**Method:** mitmproxy interception on physical device")
    if meta.get("bundle_id"):
        a(f"**Bundle ID:** {meta['bundle_id']}")
    if meta.get("app_version"):
        a(f"**App version:** {meta['app_version']}")
    a(f"**Platform:** {platform.title()}")
    a("")

    # Legal basis
    a("## Legal basis for this audit")
    a("")
    a(LEGAL_PARA_1.format(app_name=app_name))
    a("")
    a(LEGAL_PARA_2)
    a("")
    a(LEGAL_PARA_3)
    a("")

    # Results
    a("## Results")
    a("")

    # Meta
    a(f"### Meta SDK (Facebook){' — v' + meta['sdk_version'] if meta['sdk_version'] else ''}")
    a("")
    a("| Check | Status |")
    a("|-------|--------|")
    a(f"| SDK integrated | {'OK' if meta['present'] else 'NO'} |")
    a(f"| Advanced Matching (hashed email) | {'OK — ud contains: ' + ', '.join(meta['ud_content'].keys()) if meta['advanced_matching'] else '**KO** — ud={{}} (empty)'} |")
    a(f"| Custom Events | {'OK — ' + ', '.join(set(e['name'] for e in meta['custom_events'] if e['name'] not in {'fb_mobile_activate_app','fb_mobile_deactivate_app','fb_sdk_initialize','fb_sdk_background_status_available','fb_mobile_ate_status'})) if not meta['auto_events_only'] else '**KO** — only SDK auto events'} |")
    a(f"| IDFA transmitted | {'OK' if meta['idfa'] and meta['idfa'] != '00000000-0000-0000-0000-000000000000' else 'NO (zeros)'} |")
    a(f"| ATT tracking enabled | {'OK' if meta['att_enabled'] else 'NO'} |")
    a("")

    if meta["event_names"]:
        a(f"**Events observed:** {', '.join(meta['event_names'])}")
        a("")

    # Adjust
    aj_extras = []
    if adjust.get("sdk_version"):
        aj_extras.append(f"v{adjust['sdk_version']}")
    if adjust.get("app_token"):
        aj_extras.append(f"App Token {adjust['app_token']}")
    a(f"### Adjust{' — ' + ' — '.join(aj_extras) if aj_extras else ''}")
    a("")
    a("| Check | Status |")
    a("|-------|--------|")
    a(f"| SDK integrated | {'OK' if adjust['present'] else 'NO'} |")
    a(f"| Partner Params (email, user_id) | {'OK — ' + str(adjust['partner_params']) if adjust['partner_params'] else '**KO** — none'} |")
    a(f"| Callback Params | {'OK — ' + str(adjust['callback_params']) if adjust['callback_params'] else '**KO** — none'} |")
    a(f"| Custom Events | {'OK — tokens: ' + ', '.join(adjust['event_tokens']) if adjust['has_custom_events'] else '**KO** — only session tracked'} |")
    a(f"| IDFA transmitted | {'OK' if adjust['idfa'] else 'NO'} |")
    a(f"| ATT status | {adjust['att_status'] or 'N/A'} |")
    a(f"| fb_anon_id (Meta link) | {'OK' if adjust['fb_anon_id'] else 'NO'} |")
    a(f"| SKAdNetwork | {'OK' if adjust['skan_configured'] else 'NO'} |")
    a("")

    # AppsFlyer
    if appsflyer and appsflyer.get("present"):
        af_title_extras = []
        if appsflyer.get("sdk_version"):
            af_title_extras.append(f"v{appsflyer['sdk_version']}")
        if appsflyer.get("dev_key"):
            af_title_extras.append(f"Dev Key {appsflyer['dev_key']}")
        a(f"### AppsFlyer{' — ' + ' — '.join(af_title_extras) if af_title_extras else ''}")
        a("")
        a("| Check | Status |")
        a("|-------|--------|")
        a(f"| SDK integrated | OK ({appsflyer['request_count']} requests) |")
        a(f"| Advanced Matching | {'OK — ' + ', '.join(appsflyer['user_data_fields']) if appsflyer['advanced_matching'] else '**KO** — no user data'} |")
        a(f"| Custom Events | {'OK — ' + ', '.join(appsflyer['custom_events']) if appsflyer['has_custom_events'] else '**KO** — none'} |")
        a(f"| Customer User ID | {'OK — ' + str(appsflyer['customer_user_id']) if appsflyer['customer_user_id'] else '**KO** — not set'} |")
        a(f"| Deep links / Web-to-App | {'OK — ' + ', '.join(appsflyer['web_to_app_signals'].keys()) if appsflyer['web_to_app_signals'] else '**KO** — no signals'} |")
        a("")

    # Branch
    if branch and branch.get("present"):
        br_extras = []
        if branch.get("sdk_version"):
            br_extras.append(f"v{branch['sdk_version']}")
        if branch.get("branch_key"):
            br_extras.append(f"Key {branch['branch_key']}")
        a(f"### Branch{' — ' + ' — '.join(br_extras) if br_extras else ''}")
        a("")
        a("| Check | Status |")
        a("|-------|--------|")
        a(f"| SDK integrated | OK ({branch['request_count']} requests) |")
        a(f"| Identity set | {'OK' if branch['identity_set'] else '**KO** — not set'} |")
        a(f"| Deep links | {'OK' if branch['deep_link_detected'] else '**KO** — not detected'} |")
        a(f"| Events | {'OK — ' + ', '.join(branch['events']) if branch['events'] else '**KO** — none'} |")
        a("")

    # Other MMPs
    if other_mmps:
        for name, info in other_mmps.items():
            a(f"### {name}")
            a("")
            a(f"Detected ({info['count']} requests)")
            if info.get("events"):
                a(f"Events: {', '.join(info['events'])}")
            a("")

    # Others
    if others:
        a("### Other SDKs detected")
        a("")
        a("| SDK | Version | Requests | Notes |")
        a("|-----|---------|----------|-------|")
        for name, info in others.items():
            note = "anonymous user" if info.get("anonymous") else ""
            ver = info.get("version") or "?"
            a(f"| {name} | {ver} | {info['count']} | {note} |")
        a("")

    # Paywall compliance (Apple 3.1.1 / IAP bypass). Only render the section
    # when the session has a relevant signal — a paywall SDK, payment
    # processor traffic, or paywall product/variant events. An Android audit
    # or a non-subscription app would otherwise get an irrelevant page.
    if paywall and (paywall["has_payment_traffic"] or paywall["paywall_sdk"]
                    or paywall["superwall_variants"] or paywall["transaction_events"]):
        verdict_badge = {
            "OK": "[OK]",
            "REVIEW": "[REVIEW]",
            "HIGH_RISK": "[!!! HIGH RISK]",
        }.get(paywall["verdict"], "[?]")
        a("### Paywall compliance (Apple Guideline 3.1.1)")
        a("")
        a(f"**Verdict:** {verdict_badge} {paywall['verdict']}")
        a("")
        for reason in paywall["risk_reasons"]:
            a(f"- {reason}")
        a("")

        if paywall["paywall_sdk"]:
            a(f"**Paywall SDK:** {paywall['paywall_sdk']}")
        if paywall["store"] or paywall["storekit_version"]:
            a(f"**Store:** {paywall.get('store', '?')} ({paywall.get('storekit_version', '?')})")
        if paywall["paywall_identifier"]:
            a(f"**Paywall identifier:** `{paywall['paywall_identifier']}`")
        a("")

        if paywall["processors"]:
            a("**Payment processors contacted:**")
            a("")
            a("| Processor | Requests | Hosts |")
            a("|-----------|----------|-------|")
            for name, info in paywall["processors"].items():
                a(f"| {name} | {info['count']} | {', '.join(info['hosts'])} |")
            a("")
            if paywall["charge_attempts"]:
                a("**Observed charge attempts:**")
                a("")
                for ca in paywall["charge_attempts"]:
                    conf = f" ({ca.get('confidence')})" if ca.get("confidence") else ""
                    a(f"- `{ca['time']}` {ca['processor']} POST {ca['host']}{ca['path']}{conf}")
                a("")

        if paywall["superwall_variants"]:
            a("**Superwall variants assigned this session:**")
            a("")
            a("| variant_id | experiment_id | paywall_identifier |")
            a("|------------|---------------|---------------------|")
            for v in paywall["superwall_variants"]:
                a(f"| {v['variant_id']} | {v['experiment_id']} | `{v['paywall_identifier'] or ''}` |")
            a("")

        if paywall["superwall_products"]:
            a("**Products offered on this paywall:**")
            a("")
            a("| product_id | price | period | trial | store |")
            a("|------------|-------|--------|-------|-------|")
            for p in paywall["superwall_products"]:
                trial_cell = f"{p['trial_days']}d" if p.get("trial_days") else "?"
                a(f"| `{p['product_id']}` | {p.get('price') or '?'} {p.get('currency') or ''} | {p.get('period') or '?'} | {trial_cell} | {p.get('store') or '?'} |")
            a("")

        if paywall["mmp_attribution_forwarded"]:
            a("**MMP attribution forwarded to paywall SDK:**")
            a("")
            for k, v in paywall["mmp_attribution_forwarded"].items():
                a(f"- `{k}`: {v}")
            a("")

        a("> **Session scope disclaimer:** this audit characterizes ONE assigned variant "
          "for ONE install source. Apps using Superwall + MMP attribution commonly route paywalls "
          "by cohort (organic vs. Meta Purchase vs. App Review). To fully audit for 3.1.1 evasion, "
          "repeat the capture for installs originating from paid campaigns optimizing for purchase.")
        a("")

    # Recommendations
    a("---")
    a("")
    a("## Recommendations")
    a("")

    reco_num = 0
    if not meta["advanced_matching"] and meta["present"]:
        reco_num += 1
        a(f"### {reco_num}. Enable Meta Advanced Matching (HIGH PRIORITY)")
        a("")
        a("The `ud` field is empty. Pass at least the hashed email of the logged-in user.")
        a("")
        a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
        a(code["meta_advanced_matching"])
        a("```")
        a("")
        a("> The SDK hashes values as SHA-256 automatically. Do NOT pre-hash before calling.")
        a("")

    if meta["auto_events_only"] and meta["present"]:
        reco_num += 1
        a(f"### {reco_num}. Send Custom Events to Meta (HIGH PRIORITY)")
        a("")
        a("No business events sent. Track at least: purchase, trial start, registration.")
        a("")
        a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
        a(code["meta_events"])
        a("```")
        a("")

    if not adjust["partner_params"] and adjust["present"]:
        reco_num += 1
        a(f"### {reco_num}. Add Adjust Partner Params (MEDIUM PRIORITY)")
        a("")
        a("Adjust is not receiving any user identifier.")
        a("")
        a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
        a(code["adjust_partner_params"])
        a("```")
        a("")

    if not adjust["has_custom_events"] and adjust["present"]:
        reco_num += 1
        a(f"### {reco_num}. Track Adjust events (MEDIUM PRIORITY)")
        a("")
        a("No custom events. Event tokens must be created in the Adjust dashboard > Events.")
        a("")
        a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
        a(code["adjust_events"])
        a("```")
        a("")

    for name, info in others.items():
        if name == "RevenueCat" and info.get("anonymous"):
            reco_num += 1
            a(f"### {reco_num}. Link RevenueCat to user identifier (LOW PRIORITY)")
            a("")
            a("RevenueCat is using an anonymous ID. Identify the user to retrieve purchases across devices.")
            a("")
            a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
            a(code["revenuecat_login"])
            a("```")
            a("")

    # Next steps
    a("---")
    a("")
    a("## Next Steps")
    a("")
    a("1. Implement the high-priority recommendations")
    a("2. Make a new test build")
    a("3. Re-run the mitmproxy audit to validate the fixes")
    a("4. Verify in Meta Events Manager / Adjust Dashboard that data is flowing")

    return "\n".join(lines)


# --- PDF report ---

def generate_pdf(meta: dict, adjust: dict, others: dict, app_name: str, platform: str, output_path: str,
                  appsflyer: dict = None, branch: dict = None, other_mmps: dict = None,
                  paywall: dict = None):
    from fpdf import FPDF

    FONT_DIR = os.environ.get("AUDIT_FONT_DIR", "/System/Library/Fonts/Supplemental")
    code = CODE_EXAMPLES.get(platform, CODE_EXAMPLES["unity"])

    class AuditPDF(FPDF):
        def header(self):
            self.set_font("Arial", "B", 10)
            self.set_text_color(120, 120, 120)
            self.cell(0, 8, f"SDK Audit — {app_name} — {date.today().isoformat()}", align="R", new_x="LMARGIN", new_y="NEXT")
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font("Arial", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

        def section(self, title):
            self.set_font("Arial", "B", 14)
            self.set_text_color(30, 30, 30)
            self.ln(4)
            self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(2)

        def subsection(self, title):
            self.set_font("Arial", "B", 11)
            self.set_text_color(50, 50, 50)
            self.ln(2)
            self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")

        def body_text(self, text):
            self.set_font("Arial", "", 10)
            self.set_text_color(40, 40, 40)
            self.multi_cell(0, 5.5, text)
            self.ln(1)

        def status_line(self, label, status, ok=True):
            self.set_font("Arial", "", 10)
            self.set_text_color(40, 40, 40)
            self.cell(90, 6, f"  {label}")
            if ok:
                self.set_text_color(0, 130, 0)
                self.set_font("Arial", "B", 10)
                self.cell(0, 6, "[OK] " + status, new_x="LMARGIN", new_y="NEXT")
            else:
                self.set_text_color(200, 0, 0)
                self.set_font("Arial", "B", 10)
                self.cell(0, 6, "[KO] " + status, new_x="LMARGIN", new_y="NEXT")
            self.set_text_color(40, 40, 40)
            self.set_font("Arial", "", 10)

        def code_block(self, code_text):
            self.set_font("Courier", "", 8)
            self.set_fill_color(245, 245, 245)
            self.set_text_color(30, 30, 30)
            self.ln(1)
            for line in code_text.strip().split("\n"):
                truncated = line[:105] + "..." if len(line) > 108 else line
                self.cell(0, 4.5, "  " + truncated, fill=True, new_x="LMARGIN", new_y="NEXT")
            self.ln(2)
            self.set_font("Arial", "", 10)

        def bold_text(self, text):
            self.set_font("Arial", "B", 10)
            self.set_text_color(40, 40, 40)
            self.multi_cell(0, 5.5, text)
            self.set_font("Arial", "", 10)
            self.ln(1)

    pdf = AuditPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    try:
        pdf.add_font("Arial", "", os.path.join(FONT_DIR, "Arial.ttf"))
        pdf.add_font("Arial", "B", os.path.join(FONT_DIR, "Arial Bold.ttf"))
        pdf.add_font("Arial", "I", os.path.join(FONT_DIR, "Arial Italic.ttf"))
        pdf.add_font("Courier", "", os.path.join(FONT_DIR, "Courier New.ttf"))
    except (FileNotFoundError, OSError) as e:
        raise RuntimeError(
            f"TTF fonts not found in {FONT_DIR}. "
            f"Set AUDIT_FONT_DIR env var to a directory containing Arial.ttf, Arial Bold.ttf, "
            f"Arial Italic.ttf, and Courier New.ttf. Error: {e}"
        )
    pdf.add_page()

    # Title
    pdf.set_font("Arial", "B", 20)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 15, f"SDK Audit — {app_name}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Arial", "", 11)
    pdf.set_text_color(100, 100, 100)
    if meta.get("bundle_id"):
        pdf.cell(0, 7, f"{meta['bundle_id']} — App version {meta.get('app_version', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Date: {date.today().isoformat()} | Method: mitmproxy", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Platform: {platform.title()}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Legal basis
    pdf.section("Legal basis for this audit")
    pdf.body_text(LEGAL_PARA_1.format(app_name=app_name))
    pdf.ln(2)
    pdf.body_text(LEGAL_PARA_2)
    pdf.ln(2)
    pdf.body_text(LEGAL_PARA_3)
    pdf.ln(4)

    # Results
    pdf.section("Results")

    pdf.subsection(f"Meta SDK (Facebook){' — v' + meta['sdk_version'] if meta['sdk_version'] else ''}")
    pdf.status_line("SDK integrated", "OK" if meta["present"] else "NO", ok=meta["present"])
    if meta["present"]:
        pdf.status_line("Advanced Matching (hashed email)", "ud contains data" if meta["advanced_matching"] else "ud={} (empty)", ok=meta["advanced_matching"])
        pdf.status_line("Custom Events", "business events present" if not meta["auto_events_only"] else "only SDK auto events", ok=not meta["auto_events_only"])
        has_idfa = meta["idfa"] and meta["idfa"] != "00000000-0000-0000-0000-000000000000"
        pdf.status_line("IDFA transmitted", "OK" if has_idfa else "NO (zeros)", ok=has_idfa)

    aj_extras_pdf = []
    if adjust.get("sdk_version"):
        aj_extras_pdf.append(f"v{adjust['sdk_version']}")
    if adjust.get("app_token"):
        aj_extras_pdf.append(f"App Token {adjust['app_token']}")
    pdf.subsection(f"Adjust{' — ' + ' — '.join(aj_extras_pdf) if aj_extras_pdf else ''}")
    pdf.status_line("SDK integrated", "OK" if adjust["present"] else "NO", ok=adjust["present"])
    if adjust["present"]:
        pdf.status_line("Partner Params", "present" if adjust["partner_params"] else "none", ok=bool(adjust["partner_params"]))
        pdf.status_line("Custom Events", "tokens: " + ", ".join(adjust["event_tokens"]) if adjust["has_custom_events"] else "session only", ok=adjust["has_custom_events"])
        pdf.status_line("IDFA transmitted", "OK" if adjust["idfa"] else "NO", ok=bool(adjust["idfa"]))
        pdf.status_line("fb_anon_id (Meta link)", "OK" if adjust["fb_anon_id"] else "NO", ok=bool(adjust["fb_anon_id"]))
        pdf.status_line("SKAdNetwork", "configured" if adjust["skan_configured"] else "NO", ok=adjust["skan_configured"])

    if appsflyer and appsflyer.get("present"):
        af_extras_pdf = []
        if appsflyer.get("sdk_version"):
            af_extras_pdf.append(f"v{appsflyer['sdk_version']}")
        if appsflyer.get("dev_key"):
            af_extras_pdf.append(f"Dev Key {appsflyer['dev_key']}")
        pdf.subsection(f"AppsFlyer{' — ' + ' — '.join(af_extras_pdf) if af_extras_pdf else ''}")
        pdf.status_line("SDK integrated", f"OK ({appsflyer['request_count']} req.)", ok=True)
        pdf.status_line("Advanced Matching", ', '.join(appsflyer['user_data_fields']) if appsflyer['advanced_matching'] else "no user data", ok=appsflyer['advanced_matching'])
        pdf.status_line("Custom Events", ', '.join(appsflyer['custom_events']) if appsflyer['has_custom_events'] else "none", ok=appsflyer['has_custom_events'])
        pdf.status_line("Customer User ID", str(appsflyer['customer_user_id']) if appsflyer['customer_user_id'] else "not set", ok=bool(appsflyer['customer_user_id']))
        pdf.status_line("Deep links / Web-to-App", ', '.join(appsflyer['web_to_app_signals'].keys()) if appsflyer['web_to_app_signals'] else "no signals", ok=bool(appsflyer['web_to_app_signals']))

    if branch and branch.get("present"):
        br_extras_pdf = []
        if branch.get("sdk_version"):
            br_extras_pdf.append(f"v{branch['sdk_version']}")
        if branch.get("branch_key"):
            br_extras_pdf.append(f"Key {branch['branch_key']}")
        pdf.subsection(f"Branch{' — ' + ' — '.join(br_extras_pdf) if br_extras_pdf else ''}")
        pdf.status_line("SDK integrated", f"OK ({branch['request_count']} req.)", ok=True)
        pdf.status_line("Identity set", "OK" if branch['identity_set'] else "not set", ok=branch['identity_set'])
        pdf.status_line("Deep links", "OK" if branch['deep_link_detected'] else "not detected", ok=branch['deep_link_detected'])

    if other_mmps:
        for name, info in other_mmps.items():
            pdf.subsection(name)
            pdf.status_line("Detected", f"{info['count']} req.", ok=True)
            if info.get("events"):
                pdf.body_text(f"Events: {', '.join(info['events'])}")

    if others:
        pdf.subsection("Other SDKs")
        for name, info in others.items():
            note = "anonymous" if info.get("anonymous") else "OK"
            ver = info.get("version")
            ver_suffix = f", v{ver}" if ver else ""
            pdf.status_line(name, f"{note} ({info['count']} req.{ver_suffix})", ok=not info.get("anonymous"))

    # Paywall compliance (Apple 3.1.1). Same gate as the Markdown section:
    # suppress when there is no paywall SDK, no payment traffic, and no
    # Superwall variant events. An Android audit gets no irrelevant page.
    if paywall and (paywall["has_payment_traffic"] or paywall["paywall_sdk"]
                    or paywall["superwall_variants"] or paywall["transaction_events"]):
        pdf.add_page()
        pdf.section("Paywall Compliance (Apple 3.1.1)")

        verdict = paywall["verdict"]
        if verdict == "HIGH_RISK":
            pdf.set_fill_color(230, 80, 80); pdf.set_text_color(255, 255, 255)
            banner = "[!!! HIGH RISK] Direct external payment charge observed"
        elif verdict == "REVIEW":
            pdf.set_fill_color(230, 180, 60); pdf.set_text_color(40, 40, 40)
            banner = "[REVIEW] Payment processor infra loaded OR suspicious variant — investigate"
        else:
            pdf.set_fill_color(80, 180, 80); pdf.set_text_color(255, 255, 255)
            banner = "[OK] No external payment traffic detected this session"
        pdf.set_font("Arial", "B", 11)
        pdf.cell(0, 10, banner, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(40, 40, 40)
        pdf.ln(3)

        for reason in paywall["risk_reasons"]:
            pdf.body_text(f"\u2022 {reason}")

        pdf.ln(2)
        pdf.status_line("Paywall SDK", paywall["paywall_sdk"] or "none detected", ok=bool(paywall["paywall_sdk"]))
        pdf.status_line("Store", f"{paywall.get('store') or '?'} ({paywall.get('storekit_version') or '?'})",
                        ok=paywall.get("store") == "APP_STORE")
        pdf.status_line("Payment processors", ", ".join(paywall["processors"].keys()) or "none",
                        ok=not paywall["has_payment_traffic"])
        pdf.status_line("Charge attempt (POST)", "YES - bypass confirmed" if paywall["has_charge_attempt"] else "not observed",
                        ok=not paywall["has_charge_attempt"])
        if paywall["paywall_identifier"]:
            pdf.ln(1)
            pdf.body_text(f"Paywall identifier: {paywall['paywall_identifier']}")

        if paywall["superwall_variants"]:
            pdf.ln(2)
            pdf.subsection("Superwall variants assigned (this session)")
            for v in paywall["superwall_variants"]:
                pdf.body_text(f"variant_id={v['variant_id']}  experiment_id={v['experiment_id']}  paywall={v['paywall_identifier'] or ''}")

        if paywall["superwall_products"]:
            pdf.ln(2)
            pdf.subsection("Products offered")
            for p in paywall["superwall_products"]:
                trial = f"  trial={p['trial_days']}d" if p.get("trial_days") else ""
                pdf.body_text(f"{p['product_id']} — {p.get('price') or '?'} {p.get('currency') or ''} / {p.get('period') or '?'}{trial}  ({p.get('store') or '?'})")

        if paywall["charge_attempts"]:
            pdf.ln(2)
            pdf.subsection("Charge attempts observed")
            for ca in paywall["charge_attempts"]:
                conf = ca.get("confidence", "")
                # Color by confidence so the reader immediately sees whether
                # the verdict rests on a known charge endpoint (high, red)
                # or the non-fingerprint POST heuristic (orange).
                if conf == "high":
                    pdf.set_text_color(200, 0, 0)
                    tag = "[HIGH CONFIDENCE]"
                elif conf == "heuristic":
                    pdf.set_text_color(200, 120, 0)
                    tag = "[HEURISTIC]"
                else:
                    tag = ""
                pdf.body_text(f"{tag}  {ca['time']}  {ca['processor']}  POST {ca['host']}{ca['path']}")
                pdf.set_text_color(40, 40, 40)

        if paywall["mmp_attribution_forwarded"]:
            pdf.ln(2)
            pdf.subsection("MMP attribution forwarded to paywall SDK")
            for k, v in paywall["mmp_attribution_forwarded"].items():
                pdf.body_text(f"{k}: {v}")

        pdf.ln(3)
        pdf.set_font("Arial", "I", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.multi_cell(0, 5, "Session scope: this audit characterizes ONE assigned variant for ONE install source. "
                             "Apps using Superwall + MMP attribution commonly route paywalls by cohort (organic vs. "
                             "Meta Purchase vs. App Review). To fully audit for 3.1.1 evasion, repeat the capture for "
                             "installs originating from paid campaigns optimizing for purchase.")
        pdf.set_font("Arial", "", 10)
        pdf.set_text_color(40, 40, 40)

    # Recommendations
    pdf.add_page()
    pdf.section("Recommendations")

    reco_num = 0
    if not meta["advanced_matching"] and meta["present"]:
        reco_num += 1
        pdf.subsection(f"{reco_num}. Enable Meta Advanced Matching (HIGH PRIORITY)")
        pdf.body_text("The ud field is empty. Pass at least the hashed email of the logged-in user.")
        pdf.bold_text(f"{platform.title()} code:")
        pdf.code_block(code["meta_advanced_matching"])
        pdf.body_text("The SDK hashes values as SHA-256 automatically. Do NOT pre-hash.")

    if meta["auto_events_only"] and meta["present"]:
        reco_num += 1
        pdf.subsection(f"{reco_num}. Send Custom Events to Meta (HIGH PRIORITY)")
        pdf.body_text("No business events sent. Track at least: purchase, trial start, registration.")
        pdf.bold_text(f"{platform.title()} code:")
        pdf.code_block(code["meta_events"])

    if not adjust["partner_params"] and adjust["present"]:
        reco_num += 1
        pdf.subsection(f"{reco_num}. Add Adjust Partner Params (MEDIUM PRIORITY)")
        pdf.body_text("Adjust is not receiving any user identifier.")
        pdf.bold_text(f"{platform.title()} code:")
        pdf.code_block(code["adjust_partner_params"])

    if not adjust["has_custom_events"] and adjust["present"]:
        reco_num += 1
        pdf.subsection(f"{reco_num}. Track Adjust events (MEDIUM PRIORITY)")
        pdf.body_text("No custom events. Create event tokens in the Adjust Dashboard > Events.")
        pdf.bold_text(f"{platform.title()} code:")
        pdf.code_block(code["adjust_events"])

    for name, info in others.items():
        if name == "RevenueCat" and info.get("anonymous"):
            reco_num += 1
            pdf.subsection(f"{reco_num}. Link RevenueCat to user identifier (LOW PRIORITY)")
            pdf.body_text("RevenueCat is using an anonymous ID. Identify the user for cross-device continuity.")
            pdf.bold_text(f"{platform.title()} code:")
            pdf.code_block(code["revenuecat_login"])

    # Next steps
    pdf.section("Next Steps")
    pdf.body_text("1. Implement the high-priority recommendations")
    pdf.body_text("2. Make a new test build")
    pdf.body_text("3. Re-run the mitmproxy audit to validate the fixes")
    pdf.body_text("4. Verify in Meta Events Manager / Adjust Dashboard")

    pdf.output(output_path)


# --- Main ---

def main():
    parser = argparse.ArgumentParser(description="Generate SDK audit report from mitmproxy capture")
    parser.add_argument("--app-name", default=None, help="App name for the report title")
    parser.add_argument("--platform", choices=["unity", "swift", "kotlin", "react-native"], default="swift",
                        help="Platform for code examples (default: swift)")
    parser.add_argument("--capture-file", default=CAPTURE_FILE, help=f"Path to capture JSON (default: {CAPTURE_FILE})")
    parser.add_argument("--output-dir", default=OUTPUT_DIR, help=f"Output directory (default: {OUTPUT_DIR})")
    args = parser.parse_args()

    if not os.path.exists(args.capture_file):
        print(f"Error: capture file not found: {args.capture_file}")
        print("Run mitmproxy-sdk-capture/run.sh first, then use the app, then generate the report.")
        sys.exit(1)

    with open(args.capture_file) as f:
        data = json.load(f)

    meta = analyze_meta(data.get("meta", []))
    adjust = analyze_adjust(data.get("adjust", []))
    appsflyer = analyze_appsflyer(data.get("appsflyer", []))
    branch = analyze_branch(data.get("branch", []))
    other_mmps = analyze_other_mmps(data.get("other_mmps", []))
    others = analyze_other(data.get("other_sdks", []))
    paywall = analyze_paywall_compliance(data.get("payment", []), data.get("other_sdks", []))

    # Auto-detect app name from bundle_id (try meta first, then appsflyer)
    app_name = args.app_name
    if not app_name:
        for src in [meta, appsflyer]:
            bundle = src.get("bundle_id") or src.get("app_id")
            if bundle:
                app_name = bundle.split(".")[-1].title()
                break
    if not app_name:
        app_name = "App"

    today = date.today().isoformat()
    safe_name = re.sub(r"[^\w\-. ]", "_", app_name.lower())
    base = f"{safe_name}-sdk-audit-{today}"

    extra = dict(appsflyer=appsflyer, branch=branch, other_mmps=other_mmps, paywall=paywall)

    # Markdown
    md_path = os.path.join(args.output_dir, f"{base}.md")
    md_content = generate_markdown(meta, adjust, others, app_name, args.platform, **extra)
    with open(md_path, "w") as f:
        f.write(md_content)
    print(f"Markdown: {md_path}")

    # PDF
    pdf_path = os.path.join(args.output_dir, f"{base}.pdf")
    try:
        generate_pdf(meta, adjust, others, app_name, args.platform, pdf_path, **extra)
        print(f"PDF:      {pdf_path}")
    except ImportError:
        print("Warning: fpdf2 not installed, skipping PDF. Install with: pip3 install fpdf2")
    except Exception as e:
        print(f"Warning: PDF generation failed: {e}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"SUMMARY: {app_name}")
    print(f"{'='*60}")
    issues = 0

    # Meta checks
    if meta["present"] and not meta["advanced_matching"]:
        print("  [KO] Meta Advanced Matching not configured")
        issues += 1
    if meta["present"] and meta["auto_events_only"]:
        print("  [KO] Meta Custom Events not sent")
        issues += 1

    # Adjust checks
    if adjust["present"] and not adjust["partner_params"]:
        print("  [KO] Adjust Partner Params missing")
        issues += 1
    if adjust["present"] and not adjust["has_custom_events"]:
        print("  [KO] Adjust Custom Events not sent")
        issues += 1

    # AppsFlyer checks
    if appsflyer["present"]:
        print(f"  [INFO] AppsFlyer detected ({appsflyer['request_count']} requests)")
        if not appsflyer["advanced_matching"]:
            print("  [KO] AppsFlyer Advanced Matching not configured (no user data fields)")
            issues += 1
        else:
            print(f"  [OK] AppsFlyer Advanced Matching: {', '.join(appsflyer['user_data_fields'])}")
        if not appsflyer["has_custom_events"]:
            print("  [KO] AppsFlyer Custom Events not sent")
            issues += 1
        else:
            print(f"  [OK] AppsFlyer Events: {', '.join(appsflyer['custom_events'])}")
        if appsflyer["web_to_app_signals"]:
            print(f"  [INFO] Web-to-app signals: {', '.join(appsflyer['web_to_app_signals'].keys())}")
        if appsflyer["customer_user_id"]:
            print(f"  [OK] AppsFlyer Customer User ID set")
        else:
            print("  [KO] AppsFlyer Customer User ID not set")
            issues += 1

    # Branch checks
    if branch["present"]:
        print(f"  [INFO] Branch detected ({branch['request_count']} requests)")
        if not branch["identity_set"]:
            print("  [KO] Branch identity not set")
            issues += 1

    # Other MMPs
    for name, info in other_mmps.items():
        print(f"  [INFO] {name} detected ({info['count']} requests)")

    # Other SDKs
    for name, info in others.items():
        if name == "RevenueCat" and info.get("anonymous"):
            print("  [KO] RevenueCat user not identified")
            issues += 1

    # Paywall compliance (Apple 3.1.1)
    if paywall["has_payment_traffic"] or paywall["paywall_sdk"]:
        badge = {"OK": "[OK]", "REVIEW": "[REVIEW]", "HIGH_RISK": "[!!! HIGH RISK]"}.get(paywall["verdict"], "[?]")
        print(f"  {badge} Paywall compliance: {paywall['verdict']}")
        if paywall["processors"]:
            print(f"         processors: {', '.join(paywall['processors'].keys())}")
        if paywall["paywall_identifier"]:
            print(f"         paywall_id: {paywall['paywall_identifier']}")
        if paywall["verdict"] == "HIGH_RISK":
            issues += 1

    if issues == 0:
        print("  All checks passed!")
    else:
        print(f"\n  {issues} issue(s) found — see report for recommendations")


if __name__ == "__main__":
    main()
