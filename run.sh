#!/bin/bash
# Capture MMP & SDK traffic from a mobile app via mitmproxy.
#
# One-time device setup:
#   1. Set HTTP proxy on the phone: <your Mac's IP on the same Wi-Fi/VPN>, port 8080
#      (any LAN-reachable IP works: local Wi-Fi, Tailscale, ngrok, etc.)
#   2. Open http://mitm.it in Safari/Chrome on the phone, install the certificate
#   3. iOS: Settings > General > VPN & Device Management > mitmproxy > Trust
#   4. iOS: Settings > General > About > Certificate Trust Settings > enable mitmproxy
#      Android: install as a user CA cert (system CA requires root + recompile of the app
#               with networkSecurityConfig that trusts user certs)
#
# Strategy: capture ALL traffic, classify in capture.py post-hoc.
# Only --ignore-hosts for Apple/Google system domains (cert pinning breaks them).
# No --allow-hosts whitelist — ensures we never miss SDKs like Superwall, Adapty, etc.
#
# Usage:
#   ./run.sh              # start capture
#   Ctrl+C                # stop and print summary
#
# Output:
#   - Live in terminal (known SDKs labeled, unknown hosts shown)
#   - Summary on stop
#   - Full JSON in /tmp/mitmproxy_capture.json (written continuously, atomic)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

mitmdump \
  -s "$SCRIPT_DIR/capture.py" \
  --set console_eventlog_verbosity=error \
  --set connection_strategy=lazy \
  --ignore-hosts "apple\\.com|icloud\\.com|icloud-content\\.com|mzstatic\\.com|cdn-apple\\.com|googleapis\\.com|gstatic\\.com|google\\.com|googleusercontent\\.com|googlesyndication\\.com|doubleclick\\.net|googleadservices\\.com"
