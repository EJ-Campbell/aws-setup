#!/usr/bin/env bash
# Report whether the Google OAuth client accepts the Cloudflare Access callback URL.
#
# WHY THIS EXISTS: the OAuth client is the one thing in this setup that cannot be managed
# by terraform. Google publishes no API for "Web application" clients or their authorized
# redirect URIs -- the Cloud Console drives a private backend -- so a provider cannot wrap
# it. (google_iap_client looks like the answer and is not: the IAP OAuth Admin API was shut
# down in March 2026, and even before that its resource had no redirect-URI field at all.)
#
# That leaves a manual step terraform cannot see. Without this check, forgetting it is
# invisible until a human clicks "Sign in with Google" and gets redirect_uri_mismatch.
#
# HOW IT WORKS: ask Google to authorize, and read what it hands back. A registered URI
# redirects on toward a sign-in page; an unregistered one comes back with an authError
# payload that base64-decodes to the real reason.
#
# CONTRACT: terraform's external data source demands valid JSON on stdout and exit 0. This
# always exits 0 and reports the problem in the payload instead, so a network blip becomes
# a warning rather than something that blocks every apply.
set -uo pipefail

eval "$(jq -r '@sh "CID=\(.client_id) URI=\(.redirect_uri)"')"
ENC=$(jq -rn --arg u "$URI" '$u|@uri')

LOC=$(curl -s --max-time 15 -o /dev/null -w '%{redirect_url}' \
  "https://accounts.google.com/o/oauth2/v2/auth?client_id=${CID}&response_type=code&scope=openid%20email&redirect_uri=${ENC}" \
  2>/dev/null)

if [ -z "$LOC" ]; then
  STATUS=unreachable
elif printf '%s' "$LOC" | grep -q authError; then
  RAW=$(printf '%s' "$LOC" | sed -n 's/.*authError=\([^&]*\).*/\1/p' | tr '_-' '/+')
  # base64url without padding: restore it or base64 -d refuses the input.
  PAD=$(((4 - ${#RAW} % 4) % 4))
  [ "$PAD" -gt 0 ] && RAW="${RAW}$(printf '=%.0s' $(seq 1 "$PAD"))"
  MSG=$(printf '%s' "$RAW" | base64 -d 2>/dev/null | tr -dc '[:print:]' || true)
  case "$MSG" in
  *redirect_uri_mismatch*) STATUS=redirect_uri_mismatch ;;
  *invalid_client* | *"OAuth client was not found"* | *deleted_client*) STATUS=invalid_client ;;
  *) STATUS=error ;;
  esac
else
  STATUS=ok
fi

jq -n --arg status "$STATUS" '{status: $status}'
