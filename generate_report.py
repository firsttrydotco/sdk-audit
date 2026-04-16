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
            sdks[name] = {"count": 0, "anonymous": False}
        sdks[name]["count"] += 1
        if is_anonymous:
            sdks[name]["anonymous"] = True

    return sdks


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
                      appsflyer: dict = None, branch: dict = None, other_mmps: dict = None) -> str:
    code = CODE_EXAMPLES.get(platform, CODE_EXAMPLES["unity"])
    lines = []
    a = lines.append

    a(f"# Audit SDK \u2014 {app_name}")
    a(f"")
    a(f"**Date :** {date.today().isoformat()}")
    a(f"**M\u00e9thode :** Interception mitmproxy sur device physique")
    if meta.get("bundle_id"):
        a(f"**Bundle ID :** {meta['bundle_id']}")
    if meta.get("app_version"):
        a(f"**App version :** {meta['app_version']}")
    a(f"**Plateforme :** {platform.title()}")
    a("")

    # Results
    a("## R\u00e9sultats")
    a("")

    # Meta
    a(f"### Meta SDK (Facebook){' \u2014 v' + meta['sdk_version'] if meta['sdk_version'] else ''}")
    a("")
    a("| Check | Statut |")
    a("|-------|--------|")
    a(f"| SDK int\u00e9gr\u00e9 | {'OK' if meta['present'] else 'NON'} |")
    a(f"| Advanced Matching (email hash\u00e9) | {'OK \u2014 ud contient: ' + ', '.join(meta['ud_content'].keys()) if meta['advanced_matching'] else '**KO** \u2014 ud={{}} (vide)'} |")
    a(f"| Custom Events | {'OK \u2014 ' + ', '.join(set(e['name'] for e in meta['custom_events'] if e['name'] not in {'fb_mobile_activate_app','fb_mobile_deactivate_app','fb_sdk_initialize','fb_sdk_background_status_available','fb_mobile_ate_status'})) if not meta['auto_events_only'] else '**KO** \u2014 seuls events auto SDK'} |")
    a(f"| IDFA transmis | {'OK' if meta['idfa'] and meta['idfa'] != '00000000-0000-0000-0000-000000000000' else 'NON (zeros)'} |")
    a(f"| ATT tracking enabled | {'OK' if meta['att_enabled'] else 'NON'} |")
    a("")

    if meta["event_names"]:
        a(f"**Events observ\u00e9s :** {', '.join(meta['event_names'])}")
        a("")

    # Adjust
    a(f"### Adjust{' \u2014 App Token ' + adjust['app_token'] if adjust['app_token'] else ''}")
    a("")
    a("| Check | Statut |")
    a("|-------|--------|")
    a(f"| SDK int\u00e9gr\u00e9 | {'OK' if adjust['present'] else 'NON'} |")
    a(f"| Partner Params (email, user_id) | {'OK \u2014 ' + str(adjust['partner_params']) if adjust['partner_params'] else '**KO** \u2014 aucun'} |")
    a(f"| Callback Params | {'OK \u2014 ' + str(adjust['callback_params']) if adjust['callback_params'] else '**KO** \u2014 aucun'} |")
    a(f"| Custom Events | {'OK \u2014 tokens: ' + ', '.join(adjust['event_tokens']) if adjust['has_custom_events'] else '**KO** \u2014 seule session track\u00e9e'} |")
    a(f"| IDFA transmis | {'OK' if adjust['idfa'] else 'NON'} |")
    a(f"| ATT status | {adjust['att_status'] or 'N/A'} |")
    a(f"| fb_anon_id (lien Meta) | {'OK' if adjust['fb_anon_id'] else 'NON'} |")
    a(f"| SKAdNetwork | {'OK' if adjust['skan_configured'] else 'NON'} |")
    a("")

    # AppsFlyer
    if appsflyer and appsflyer.get("present"):
        a(f"### AppsFlyer{' \u2014 Dev Key ' + appsflyer['dev_key'] if appsflyer.get('dev_key') else ''}")
        a("")
        a("| Check | Statut |")
        a("|-------|--------|")
        a(f"| SDK int\u00e9gr\u00e9 | OK ({appsflyer['request_count']} requ\u00eates) |")
        a(f"| Advanced Matching | {'OK \u2014 ' + ', '.join(appsflyer['user_data_fields']) if appsflyer['advanced_matching'] else '**KO** \u2014 aucun user data'} |")
        a(f"| Custom Events | {'OK \u2014 ' + ', '.join(appsflyer['custom_events']) if appsflyer['has_custom_events'] else '**KO** \u2014 aucun'} |")
        a(f"| Customer User ID | {'OK \u2014 ' + str(appsflyer['customer_user_id']) if appsflyer['customer_user_id'] else '**KO** \u2014 non d\u00e9fini'} |")
        a(f"| Deep links / Web-to-App | {'OK \u2014 ' + ', '.join(appsflyer['web_to_app_signals'].keys()) if appsflyer['web_to_app_signals'] else '**KO** \u2014 aucun signal'} |")
        a("")

    # Branch
    if branch and branch.get("present"):
        a(f"### Branch{' \u2014 Key ' + branch['branch_key'] if branch.get('branch_key') else ''}")
        a("")
        a("| Check | Statut |")
        a("|-------|--------|")
        a(f"| SDK int\u00e9gr\u00e9 | OK ({branch['request_count']} requ\u00eates) |")
        a(f"| Identity set | {'OK' if branch['identity_set'] else '**KO** \u2014 non d\u00e9fini'} |")
        a(f"| Deep links | {'OK' if branch['deep_link_detected'] else '**KO** \u2014 non d\u00e9tect\u00e9'} |")
        a(f"| Events | {'OK \u2014 ' + ', '.join(branch['events']) if branch['events'] else '**KO** \u2014 aucun'} |")
        a("")

    # Other MMPs
    if other_mmps:
        for name, info in other_mmps.items():
            a(f"### {name}")
            a("")
            a(f"D\u00e9tect\u00e9 ({info['count']} requ\u00eates)")
            if info.get("events"):
                a(f"Events: {', '.join(info['events'])}")
            a("")

    # Others
    if others:
        a("### Autres SDKs d\u00e9tect\u00e9s")
        a("")
        a("| SDK | Requ\u00eates | Notes |")
        a("|-----|----------|-------|")
        for name, info in others.items():
            note = "utilisateur anonyme" if info.get("anonymous") else ""
            a(f"| {name} | {info['count']} | {note} |")
        a("")

    # Recommendations
    a("---")
    a("")
    a("## Recommandations")
    a("")

    reco_num = 0
    if not meta["advanced_matching"] and meta["present"]:
        reco_num += 1
        a(f"### {reco_num}. Activer l'Advanced Matching Meta (PRIORIT\u00c9 HAUTE)")
        a("")
        a("Le champ `ud` est vide. Transmettre au minimum l'email hash\u00e9 de l'utilisateur connect\u00e9.")
        a("")
        a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
        a(code["meta_advanced_matching"])
        a("```")
        a("")
        a("> Le SDK se charge du hachage SHA-256 automatiquement. Ne PAS hasher avant d'appeler cette m\u00e9thode.")
        a("")

    if meta["auto_events_only"] and meta["present"]:
        reco_num += 1
        a(f"### {reco_num}. Envoyer les Custom Events \u00e0 Meta (PRIORIT\u00c9 HAUTE)")
        a("")
        a("Aucun event business n'est envoy\u00e9. Tracker au minimum : purchase, trial start, registration.")
        a("")
        a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
        a(code["meta_events"])
        a("```")
        a("")

    if not adjust["partner_params"] and adjust["present"]:
        reco_num += 1
        a(f"### {reco_num}. Ajouter les Partner Params Adjust (PRIORIT\u00c9 MOYENNE)")
        a("")
        a("Adjust ne re\u00e7oit aucun identifiant utilisateur.")
        a("")
        a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
        a(code["adjust_partner_params"])
        a("```")
        a("")

    if not adjust["has_custom_events"] and adjust["present"]:
        reco_num += 1
        a(f"### {reco_num}. Tracker les events Adjust (PRIORIT\u00c9 MOYENNE)")
        a("")
        a("Aucun event custom. Les `eventToken` doivent \u00eatre cr\u00e9\u00e9s dans le dashboard Adjust > Events.")
        a("")
        a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
        a(code["adjust_events"])
        a("```")
        a("")

    for name, info in others.items():
        if name == "RevenueCat" and info.get("anonymous"):
            reco_num += 1
            a(f"### {reco_num}. Lier RevenueCat \u00e0 l'identifiant utilisateur (PRIORIT\u00c9 BASSE)")
            a("")
            a("RevenueCat utilise un ID anonyme. Identifier l'utilisateur pour retrouver les achats cross-device.")
            a("")
            a(f"```{'csharp' if platform == 'unity' else 'javascript' if platform == 'react-native' else platform}")
            a(code["revenuecat_login"])
            a("```")
            a("")

    # Next steps
    a("---")
    a("")
    a("## Prochaines \u00e9tapes")
    a("")
    a("1. Impl\u00e9menter les recommandations priorit\u00e9 haute")
    a("2. Faire un nouveau build de test")
    a("3. Relancer l'audit mitmproxy pour valider les corrections")
    a("4. V\u00e9rifier dans Meta Events Manager / Adjust Dashboard que les donn\u00e9es remontent")

    return "\n".join(lines)


# --- PDF report ---
#
# Uses fpdf2's built-in Helvetica + Courier (PDF base-14 fonts, guaranteed
# present in every PDF reader on every OS — zero TTF, zero setup). Their
# encoding is Latin-1, which covers the accented characters we use; the
# few non-Latin-1 typographic chars (em-dash, ellipsis, curly quotes, euro)
# are normalized to Latin-1 equivalents by the AuditPDF wrapper.

_LATIN1_FALLBACKS = str.maketrans({
    "\u2014": "-",   # em dash
    "\u2013": "-",   # en dash
    "\u2026": "...", # ellipsis
    "\u20AC": "EUR", # euro
    "\u2018": "'", "\u2019": "'",  # curly singles
    "\u201C": '"', "\u201D": '"',  # curly doubles
})


def _latin1(s):
    return s.translate(_LATIN1_FALLBACKS) if isinstance(s, str) else s


def generate_pdf(meta: dict, adjust: dict, others: dict, app_name: str, platform: str, output_path: str,
                  appsflyer: dict = None, branch: dict = None, other_mmps: dict = None):
    from fpdf import FPDF

    code = CODE_EXAMPLES.get(platform, CODE_EXAMPLES["unity"])

    class AuditPDF(FPDF):
        # Transparently translate the few non-Latin-1 chars we use (em-dash,
        # ellipsis, curly quotes, euro) to ASCII equivalents so the rest of
        # the report code can stay readable with normal Unicode literals.
        def cell(self, *args, **kwargs):
            if "text" in kwargs:
                kwargs["text"] = _latin1(kwargs["text"])
            elif len(args) >= 3:
                args = (args[0], args[1], _latin1(args[2]), *args[3:])
            return super().cell(*args, **kwargs)

        def multi_cell(self, *args, **kwargs):
            if "text" in kwargs:
                kwargs["text"] = _latin1(kwargs["text"])
            elif len(args) >= 3:
                args = (args[0], args[1], _latin1(args[2]), *args[3:])
            return super().multi_cell(*args, **kwargs)

        def header(self):
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(120, 120, 120)
            self.cell(0, 8, f"Audit SDK \u2014 {app_name} \u2014 {date.today().isoformat()}", align="R", new_x="LMARGIN", new_y="NEXT")
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

        def section(self, title):
            self.set_font("Helvetica", "B", 14)
            self.set_text_color(30, 30, 30)
            self.ln(4)
            self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(2)

        def subsection(self, title):
            self.set_font("Helvetica", "B", 11)
            self.set_text_color(50, 50, 50)
            self.ln(2)
            self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")

        def body_text(self, text):
            self.set_font("Helvetica", "", 10)
            self.set_text_color(40, 40, 40)
            self.multi_cell(0, 5.5, text)
            self.ln(1)

        def status_line(self, label, status, ok=True):
            self.set_font("Helvetica", "", 10)
            self.set_text_color(40, 40, 40)
            self.cell(90, 6, f"  {label}")
            if ok:
                self.set_text_color(0, 130, 0)
                self.set_font("Helvetica", "B", 10)
                self.cell(0, 6, "[OK] " + status, new_x="LMARGIN", new_y="NEXT")
            else:
                self.set_text_color(200, 0, 0)
                self.set_font("Helvetica", "B", 10)
                self.cell(0, 6, "[KO] " + status, new_x="LMARGIN", new_y="NEXT")
            self.set_text_color(40, 40, 40)
            self.set_font("Helvetica", "", 10)

        def code_block(self, code_text):
            self.set_font("Courier", "", 8)
            self.set_fill_color(245, 245, 245)
            self.set_text_color(30, 30, 30)
            self.ln(1)
            for line in code_text.strip().split("\n"):
                truncated = line[:105] + "..." if len(line) > 108 else line
                self.cell(0, 4.5, "  " + truncated, fill=True, new_x="LMARGIN", new_y="NEXT")
            self.ln(2)
            self.set_font("Helvetica", "", 10)

        def bold_text(self, text):
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(40, 40, 40)
            self.multi_cell(0, 5.5, text)
            self.set_font("Helvetica", "", 10)
            self.ln(1)

    pdf = AuditPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(20, 20, 20)
    pdf.cell(0, 15, f"Audit SDK \u2014 {app_name}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 100, 100)
    if meta.get("bundle_id"):
        pdf.cell(0, 7, f"{meta['bundle_id']} \u2014 App version {meta.get('app_version', 'N/A')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Date : {date.today().isoformat()} | M\u00e9thode : mitmproxy", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"Plateforme : {platform.title()}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)

    # Results
    pdf.section("R\u00e9sultats")

    pdf.subsection(f"Meta SDK (Facebook){' \u2014 v' + meta['sdk_version'] if meta['sdk_version'] else ''}")
    pdf.status_line("SDK int\u00e9gr\u00e9", "OK" if meta["present"] else "NON", ok=meta["present"])
    if meta["present"]:
        pdf.status_line("Advanced Matching (email hash\u00e9)", "ud contient des donn\u00e9es" if meta["advanced_matching"] else "ud={} (vide)", ok=meta["advanced_matching"])
        pdf.status_line("Custom Events", "events business pr\u00e9sents" if not meta["auto_events_only"] else "seuls events auto SDK", ok=not meta["auto_events_only"])
        has_idfa = meta["idfa"] and meta["idfa"] != "00000000-0000-0000-0000-000000000000"
        pdf.status_line("IDFA transmis", "OK" if has_idfa else "NON (zeros)", ok=has_idfa)

    pdf.subsection(f"Adjust{' \u2014 App Token ' + adjust['app_token'] if adjust['app_token'] else ''}")
    pdf.status_line("SDK int\u00e9gr\u00e9", "OK" if adjust["present"] else "NON", ok=adjust["present"])
    if adjust["present"]:
        pdf.status_line("Partner Params", "pr\u00e9sents" if adjust["partner_params"] else "aucun", ok=bool(adjust["partner_params"]))
        pdf.status_line("Custom Events", "tokens: " + ", ".join(adjust["event_tokens"]) if adjust["has_custom_events"] else "seule session", ok=adjust["has_custom_events"])
        pdf.status_line("IDFA transmis", "OK" if adjust["idfa"] else "NON", ok=bool(adjust["idfa"]))
        pdf.status_line("fb_anon_id (lien Meta)", "OK" if adjust["fb_anon_id"] else "NON", ok=bool(adjust["fb_anon_id"]))
        pdf.status_line("SKAdNetwork", "configur\u00e9" if adjust["skan_configured"] else "NON", ok=adjust["skan_configured"])

    if appsflyer and appsflyer.get("present"):
        pdf.subsection(f"AppsFlyer{' \u2014 Dev Key ' + appsflyer['dev_key'] if appsflyer.get('dev_key') else ''}")
        pdf.status_line("SDK int\u00e9gr\u00e9", f"OK ({appsflyer['request_count']} req.)", ok=True)
        pdf.status_line("Advanced Matching", ', '.join(appsflyer['user_data_fields']) if appsflyer['advanced_matching'] else "aucun user data", ok=appsflyer['advanced_matching'])
        pdf.status_line("Custom Events", ', '.join(appsflyer['custom_events']) if appsflyer['has_custom_events'] else "aucun", ok=appsflyer['has_custom_events'])
        pdf.status_line("Customer User ID", str(appsflyer['customer_user_id']) if appsflyer['customer_user_id'] else "non d\u00e9fini", ok=bool(appsflyer['customer_user_id']))
        pdf.status_line("Deep links / Web-to-App", ', '.join(appsflyer['web_to_app_signals'].keys()) if appsflyer['web_to_app_signals'] else "aucun signal", ok=bool(appsflyer['web_to_app_signals']))

    if branch and branch.get("present"):
        pdf.subsection(f"Branch{' \u2014 Key ' + branch['branch_key'] if branch.get('branch_key') else ''}")
        pdf.status_line("SDK int\u00e9gr\u00e9", f"OK ({branch['request_count']} req.)", ok=True)
        pdf.status_line("Identity set", "OK" if branch['identity_set'] else "non d\u00e9fini", ok=branch['identity_set'])
        pdf.status_line("Deep links", "OK" if branch['deep_link_detected'] else "non d\u00e9tect\u00e9", ok=branch['deep_link_detected'])

    if other_mmps:
        for name, info in other_mmps.items():
            pdf.subsection(name)
            pdf.status_line("D\u00e9tect\u00e9", f"{info['count']} req.", ok=True)
            if info.get("events"):
                pdf.body_text(f"Events: {', '.join(info['events'])}")

    if others:
        pdf.subsection("Autres SDKs")
        for name, info in others.items():
            note = "anonyme" if info.get("anonymous") else "OK"
            pdf.status_line(name, f"{note} ({info['count']} req.)", ok=not info.get("anonymous"))

    # Recommendations
    pdf.add_page()
    pdf.section("Recommandations")

    reco_num = 0
    if not meta["advanced_matching"] and meta["present"]:
        reco_num += 1
        pdf.subsection(f"{reco_num}. Activer l'Advanced Matching Meta (PRIORIT\u00c9 HAUTE)")
        pdf.body_text("Le champ ud est vide. Transmettre au minimum l'email hash\u00e9 de l'utilisateur connect\u00e9.")
        pdf.bold_text(f"Code {platform.title()} :")
        pdf.code_block(code["meta_advanced_matching"])
        pdf.body_text("Le SDK hashe automatiquement en SHA-256. Ne PAS hasher avant.")

    if meta["auto_events_only"] and meta["present"]:
        reco_num += 1
        pdf.subsection(f"{reco_num}. Envoyer les Custom Events \u00e0 Meta (PRIORIT\u00c9 HAUTE)")
        pdf.body_text("Aucun event business envoy\u00e9. Tracker au minimum : purchase, trial start, registration.")
        pdf.bold_text(f"Code {platform.title()} :")
        pdf.code_block(code["meta_events"])

    if not adjust["partner_params"] and adjust["present"]:
        reco_num += 1
        pdf.subsection(f"{reco_num}. Ajouter les Partner Params Adjust (PRIORIT\u00c9 MOYENNE)")
        pdf.body_text("Adjust ne re\u00e7oit aucun identifiant utilisateur.")
        pdf.bold_text(f"Code {platform.title()} :")
        pdf.code_block(code["adjust_partner_params"])

    if not adjust["has_custom_events"] and adjust["present"]:
        reco_num += 1
        pdf.subsection(f"{reco_num}. Tracker les events Adjust (PRIORIT\u00c9 MOYENNE)")
        pdf.body_text("Aucun event custom. Cr\u00e9er les eventToken dans Adjust Dashboard > Events.")
        pdf.bold_text(f"Code {platform.title()} :")
        pdf.code_block(code["adjust_events"])

    for name, info in others.items():
        if name == "RevenueCat" and info.get("anonymous"):
            reco_num += 1
            pdf.subsection(f"{reco_num}. Lier RevenueCat \u00e0 l'identifiant utilisateur (PRIORIT\u00c9 BASSE)")
            pdf.body_text("RevenueCat utilise un ID anonyme. Identifier l'utilisateur pour le cross-device.")
            pdf.bold_text(f"Code {platform.title()} :")
            pdf.code_block(code["revenuecat_login"])

    # Next steps
    pdf.section("Prochaines \u00e9tapes")
    pdf.body_text("1. Impl\u00e9menter les recommandations priorit\u00e9 haute")
    pdf.body_text("2. Faire un nouveau build de test")
    pdf.body_text("3. Relancer l'audit mitmproxy pour valider les corrections")
    pdf.body_text("4. V\u00e9rifier dans Meta Events Manager / Adjust Dashboard")

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

    extra = dict(appsflyer=appsflyer, branch=branch, other_mmps=other_mmps)

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

    if issues == 0:
        print("  All checks passed!")
    else:
        print(f"\n  {issues} issue(s) found — see report for recommendations")


if __name__ == "__main__":
    main()
