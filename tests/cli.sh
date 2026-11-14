#!/usr/bin/env bash
# DIVE-8315 — `5dive email connect|status|disconnect|gate|allow|server`, against
# a stubbed 5dive. Runs as root (connect writes another user's 0600 file and
# refuses anyone else), so: sudo bash tests/cli.sh
#
# The stub records every core call it gets, so each arm grades what connect
# ASKED core to do (channel, secret link), not just what it printed.
# Addresses are @example.com (the fixture rule); the self-hosted domain is
# example.com too.
set -uo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root: sudo bash $0" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/email/bin/email"
W=$(mktemp -d); GPIDS=()
trap '(( ${#GPIDS[@]} )) && kill "${GPIDS[@]}" 2>/dev/null; rm -rf "$W"' EXIT
PASS=0 FAIL=0
ok()  { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; [[ -n "${2:-}" ]] && sed 's/^/       /' <<<"$2"; }
ME="${SUDO_USER:-root}"
A=max@example.com
AU=$(tr a-z A-Z <<<"$A")

mkdir -p "$W/home/agent-max/.claude" "$W/conn" "$W/etc" "$W/spool"
cat >"$W/5dive" <<'STUB'
#!/usr/bin/env bash
echo "$*" >>"$STUB_LOG"
case "$1 $2" in
  "agent info") [[ "$3" == max ]] || exit 4
    printf '{"ok":true,"data":{"name":"max","type":"%s","channels":"%s"}}\n' "${STUB_TYPE:-claude}" "$(cat "$STUB_CHANNELS")" ;;
  "agent config") echo "${5#channels=}" >"$STUB_CHANNELS" ;;
esac
exit 0
STUB
chmod +x "$W/5dive"
echo telegram >"$W/channels"
export STUB_LOG="$W/log" STUB_CHANNELS="$W/channels"
export EMAIL_5DIVE_BIN="$W/5dive" EMAIL_CONNECTORS_DIR="$W/conn" AGENT_HOME_ROOT="$W/home" EMAIL_AGENT_USER="$ME"
export EMAIL_MAIL_ETC="$W/etc" EMAIL_MAIL_SPOOL="$W/spool" FIVE_LOCAL_ONLY_FILE="$W/local-only"
# The send check (DIVE-8347) never reaches the internet here: by default it
# meets a closed local port. Arms that need it open point it at tests/greeter.py.
# An install that gets past the check stops at once: MAIL_OPT sits under a file.
: >"$W/blocker"
# EMAIL_NO_FILTERS: setup must not apt-get rspamd/ClamAV onto the runner (DIVE-8405).
export EMAIL_NO_FILTERS=1
export EMAIL_SEND_PROBE_HOSTS="127.0.0.1:1" EMAIL_SEND_PROBE_TIMEOUT=1 EMAIL_MAIL_OPT="$W/blocker/opt"
CFG="$W/home/agent-max/.claude/channels/email/config.json"
run() { : >"$STUB_LOG"; OUT=$(bash "$BIN" "$@" 2>&1); RC=$?; }

echo "connect, a firm mailbox"
run connect max --address=$A --provider=google --password=hunter2
[[ $RC == 3 && "$OUT" == *"never an argument"* && ! -e "$CFG" ]] && ok "C1 a password on the command line is refused, nothing written" || bad "C1 password argv" "$RC $OUT"
run connect max --address=not-an-address --provider=google
[[ $RC == 3 ]] && ok "C2 a bad address is refused" || bad "C2 bad address" "$RC $OUT"
run connect max --address=$A --provider=microsoft
[[ $RC == 3 && "$OUT" == *"Microsoft sign-in"* && ! -e "$CFG" ]] && ok "C2b Microsoft 365 is refused honestly (no password IMAP there since 2022), nothing written" || bad "C2b microsoft" "$RC $OUT"
run connect max --address=$A --provider=google
[[ $RC == 6 && "$OUT" == *"secret write EMAIL_PASSWORD --connector=email-max"* && ! -e "$CFG" ]] && ok "C3 no password on the box yet: refused with the secret-write line" || bad "C3 no secret" "$RC $OUT"
run connect max --address=$A --provider=google --task=DIVE-1
[[ $RC == 6 ]] && grep -qE '^task need DIVE-1 --type=secret --secret-key=EMAIL_PASSWORD --connector=email-max ' "$W/log" \
  && ok "C3b --task opens a one-time secret link for EMAIL_PASSWORD" || bad "C3b secret link" "$RC $OUT $(cat "$W/log")"
printf 'EMAIL_PASSWORD=app-pw-1\n' >"$W/conn/email-max.env"
run connect max --address=$AU --provider=google --name=Max
[[ $RC == 0 && "$(stat -c '%a %U' "$CFG")" == "600 $ME" \
   && "$(jq -c '[.address,.mode,.imap.host,.imap.port,.imap.secure,.smtp.host,.smtp.port,.smtp.secure,.smtp.pass]' "$CFG")" == "[\"$A\",\"imap\",\"imap.gmail.com\",993,true,\"smtp.gmail.com\",465,true,\"app-pw-1\"]" \
   && "$(cat "$W/channels")" == "telegram,email" ]] \
  && ok "C4 connect writes the agent's 0600 config (google preset, address lower-cased) and turns the channel on" || bad "C4 connect" "$RC $OUT $(cat "$CFG" 2>/dev/null)"
# Core adds the channel to the box's allowlist from the manifest when channels=email is set.
! grep -q 'managed-settings' "$BIN" && grep -q '^agent config max set channels=telegram,email$' "$W/log" \
  && ok "A1 the channel goes on through core (which allowlists it); the plugin edits no box file" || bad "A1 via core" "$(cat "$W/log")"
[[ "$OUT" != *app-pw-1* ]] && ! grep -q app-pw-1 "$W/log" && ok "C4b the password is never printed or passed to core" || bad "C4b password leak"

echo "the owner's switches"
run gate max off
[[ $RC == 0 && "$(jq -r .approve_new "$CFG")" == false ]] && ok "G1 gate off writes approve_new:false" || bad "G1 gate off" "$RC $OUT"
run cap max 7
run connect max --provider=google
[[ "$(jq -c '[.approve_new,.daily_cap,.address]' "$CFG")" == "[false,7,\"$A\"]" ]] && ok "G2 a re-run of connect keeps the owner's gate, cap and address" || bad "G2 keep" "$(cat "$CFG")"
run gate max on
[[ "$(jq -r .approve_new "$CFG")" == true ]] && ok "G3 gate on again" || bad "G3 gate on"
run gate max inbound off
[[ $RC == 0 && "$(jq -c '[.approve_inbound,.approve_new]' "$CFG")" == '[false,true]' ]] && ok "G4 gate inbound off writes approve_inbound:false and leaves the send gate" || bad "G4 inbound off" "$RC $OUT $(cat "$CFG")"
run gate max sideways off
[[ $RC == 2 ]] && ok "G4b an unknown gate is refused" || bad "G4b unknown gate" "$RC $OUT"
B=$(printf 'bob@%s' example.com)
run allow max "$(tr a-z A-Z <<<"$B")" @Example.org
[[ $RC == 0 && "$(jq -c '.allowed' "$CFG")" == "[\"@example.org\",\"$B\"]" ]] && ok "G5 allow adds an address and a whole @domain, lower-cased" || bad "G5 allow" "$RC $OUT $(cat "$CFG")"
run allow max not-an-address
[[ $RC == 3 && "$(jq -c '.allowed | length' "$CFG")" == 2 ]] && ok "G5b a bad address is refused, the list unchanged" || bad "G5b bad allow" "$RC $OUT"
run connect max --provider=google
[[ "$(jq -c '[.approve_inbound,(.allowed|length)]' "$CFG")" == '[false,2]' ]] && ok "G6 a re-run of connect keeps the inbound switch and the list" || bad "G6 keep" "$(cat "$CFG")"
run allow max @example.org --remove
[[ $RC == 0 && "$(jq -c '.allowed' "$CFG")" == "[\"$B\"]" ]] && ok "G7 allow --remove takes one off" || bad "G7 remove" "$RC $OUT $(cat "$CFG")"
run gate max inbound on
run gate max sender off
[[ $RC == 0 && "$(jq -r .check_sender "$CFG")" == false && "$OUT" == *"faked colleague"* ]] && ok "G8 gate sender off writes check_sender:false and says what it opens" || bad "G8 sender off" "$RC $OUT"
run gate max spam off
[[ $RC == 3 && "$OUT" == *"provider filters spam itself"* ]] && ok "G9 spam gate on a firm mailbox is refused: the provider filters" || bad "G9 spam on imap" "$RC $OUT"
# DIVE-8405 iteration 2: an unknown mail server's sender check is believed only under the name the owner gives.
run gate max sender on
run connect max --address=$A --imap-host=mail.example.com --smtp-host=mail.example.com
[[ $RC == 0 && "$OUT" == *"not known to confirm senders"* && "$(jq -r '.trusted_authserv_id // "none"' "$CFG")" == none ]] \
  && ok "G14 an unknown mail server: connect says every mail waits until its sender check is named" || bad "G14 unknown server" "$RC $OUT"
run connect max --address=$A --imap-host=mail.example.com --smtp-host=mail.example.com --trusted-authserv-id=MX.Example.com --exchange
[[ $RC == 0 && "$OUT" != *"not known to confirm senders"* && "$(jq -c '[.trusted_authserv_id,.exchange]' "$CFG")" == '["mx.example.com",true]' ]] \
  && ok "G15 --trusted-authserv-id and --exchange are written (lower-cased) and the warning goes" || bad "G15 trusted id" "$RC $OUT $(cat "$CFG")"
run connect max --address=$A --imap-host=mail.example.com --smtp-host=mail.example.com
[[ $RC == 0 && "$(jq -c '[.trusted_authserv_id,.exchange]' "$CFG")" == '["mx.example.com",true]' ]] && ok "G15b a re-run of connect keeps them" || bad "G15b keep" "$(cat "$CFG")"
run connect max --address=$A --imap-host=mail.example.com --smtp-host=mail.example.com '--trusted-authserv-id=mx.example.com;x'
[[ $RC == 3 && "$(jq -r .trusted_authserv_id "$CFG")" == mx.example.com ]] && ok "G16 a bad server name is refused, nothing changed" || bad "G16 bad id" "$RC $OUT"
run gate max sender off   # S2c reads it back after a self-hosted connect

echo "the Resend preset (optional; direct sending stays the default)"
run server setup --domain=example.com --relay=resend
[[ $RC == 6 && "$OUT" == *"Resend API key"* && "$OUT" == *"--connector=email-relay"* && ! -e "$W/etc/server.json" ]] \
  && ok "R1 --relay=resend without a key: refused, naming the key and the one-time link, nothing written" || bad "R1 resend no key" "$RC $OUT"
run server setup --domain=example.com --relay=resend --task=DIVE-1
[[ $RC == 6 ]] && grep -q '^task need DIVE-1 --type=secret --secret-key=EMAIL_RELAY_PASSWORD --connector=email-relay --ask=.*through Resend' "$W/log" \
  && ok "R2 --task opens the one-time link for the Resend API key" || bad "R2 resend link" "$RC $OUT $(cat "$W/log")"
run server setup --domain=example.com --relay=resend --relay-host=smtp.example.com
[[ $RC == 2 ]] && ok "R3 --relay=resend with --relay-host is refused (the preset fills it in)" || bad "R3 both" "$RC $OUT"
run server setup --domain=example.com --relay=postmark
[[ $RC == 2 && "$OUT" == *"--relay-host"* ]] && ok "R4 an unknown preset is refused, pointing at --relay-host" || bad "R4 unknown preset" "$RC $OUT"

echo "can this box send? (port 25 out, DIVE-8347)"
greeter() {  # <name> <greeting>: start a fake mail server, its port in $GPORT
  local d="$W/g-$1"; mkdir -p "$d"
  python3 "$ROOT/tests/greeter.py" "$2" "$d/port" "$d/log" >/dev/null 2>&1 & GPIDS+=($!)
  local _i; for _i in $(seq 50); do [[ -s "$d/port" ]] && break; sleep 0.1; done
  GPORT=$(cat "$d/port"); : >"$d/log"
}
greeter open "220 mx.example.com ESMTP"; OPEN=127.0.0.1:$GPORT
greeter refuse "554 no service"; REFUSE=127.0.0.1:$GPORT
greeter silent silent; SILENT=127.0.0.1:$GPORT
SHUT=127.0.0.1:1
EMAIL_SEND_PROBE_HOSTS=$OPEN run server check
[[ $RC == 0 && "$OUT" == *"can send mail itself"* ]] && ok "P1 open: server check says this box can send" || bad "P1 check open" "$RC $OUT"
[[ "$(tr -d '\r' <"$W/g-open/log")" == "QUIT" ]] && ok "P1b the check only says QUIT: no HELO, no MAIL FROM, no mail" || bad "P1b probe sent more" "$(cat -A "$W/g-open/log")"
EMAIL_SEND_PROBE_HOSTS=$SHUT run server check
[[ $RC == 10 && "$OUT" == *"blocks sending mail"* && "$OUT" == *"--relay=resend"* && "$OUT" == *"--provider=google|other"* ]] \
  && ok "P2 shut: server check says the host blocks sending, offers Resend and the firm's mailbox" || bad "P2 check shut" "$RC $OUT"
EMAIL_SEND_PROBE_HOSTS="$REFUSE $SILENT" run server check
[[ $RC == 10 ]] && ok "P3 a server that answers 554, or never greets, is not an open port 25" || bad "P3 not 220" "$RC $OUT"
EMAIL_SEND_PROBE_HOSTS=$SHUT run server setup --domain=example.com
[[ $RC == 10 && "$OUT" == *"blocks sending mail"* && "$OUT" == *"--domain=example.com --relay=resend"* && "$OUT" != *"Installing"* \
   && ! -e "$W/etc/server.json" && ! -e "$W/etc/dkim.key" ]] \
  && ok "P4 shut: setup with no relay refuses, names the routes with the domain filled in, writes nothing" || bad "P4 setup shut" "$RC $OUT"
EMAIL_SEND_PROBE_HOSTS="$SHUT $OPEN" run server setup --domain=example.com
[[ "$OUT" != *"blocks sending"* && "$OUT" == *"Installing OpenAgent Mail"* ]] \
  && ok "P5 open (second provider answers): setup goes on to install, sending direct as today" || bad "P5 setup open" "$RC $OUT"
EMAIL_SEND_PROBE_HOSTS=nowhere.invalid:25 run server setup --domain=example.com
[[ "$OUT" == *"could not check sending"* && "$OUT" == *"Installing OpenAgent Mail"* ]] \
  && ok "P6 no DNS: a warning, not a false 'blocked'; setup goes on" || bad "P6 no dns" "$RC $OUT"
EMAIL_SEND_PROBE_HOSTS=$SHUT run server setup --domain=example.com --relay=resend
[[ $RC == 6 && "$OUT" != *"Checking this server can send"* ]] && ok "P7 a relay named: no port 25 check (the relay sends)" || bad "P7 relay skips" "$RC $OUT"
: >"$FIVE_LOCAL_ONLY_FILE"
EMAIL_SEND_PROBE_HOSTS=$SHUT run server check
[[ $RC == 0 && "$OUT" == *"offline"* ]] && ok "P8 local-only: mail stays in the office, nothing to check" || bad "P8 offline" "$RC $OUT"
EMAIL_SEND_PROBE_HOSTS=$SHUT run server setup --domain=example.com
[[ "$OUT" != *"blocks sending"* && "$OUT" == *"Installing OpenAgent Mail"* ]] && ok "P8b local-only: setup does not probe the internet" || bad "P8b offline setup" "$RC $OUT"
rm -f "$FIVE_LOCAL_ONLY_FILE"

echo "local-only"
: >"$FIVE_LOCAL_ONLY_FILE"
run connect max --address=$A --provider=google
[[ $RC == 10 && "$OUT" == *"local-only allow email"* ]] && ok "L1 offline: a cloud mailbox is refused, naming the IT switch" || bad "L1 offline cloud" "$RC $OUT"
run connect max --address=$A --imap-host=localhost --smtp-host=localhost
[[ $RC == 0 && "$(jq -r .imap.host "$CFG")" == localhost ]] && ok "L2 offline: a mail server on the office network (here: this box) is allowed" || bad "L2 offline LAN" "$RC $OUT"
echo email >"$W/local-only.allow"
run connect max --address=$A --provider=google
[[ $RC == 0 ]] && ok "L3 IT opened email: the cloud mailbox connects" || bad "L3 allow email" "$RC $OUT"
rm -f "$FIVE_LOCAL_ONLY_FILE" "$W/local-only.allow"

echo "self-hosted"
run connect max --self-hosted
[[ $RC == 4 && "$OUT" == *"server setup --domain="* ]] && ok "S1 no mail server yet: says how to set one up" || bad "S1 no server" "$RC $OUT"
echo '{"domain":"example.com","agents":{}}' >"$W/etc/server.json"
run connect max --self-hosted
PW=$(jq -r .smtp.pass "$CFG"); H=$(printf '%s' "$PW" | sha256sum | cut -d' ' -f1)
[[ $RC == 0 && "$(jq -c '[.address,.mode,.smtp.host,.smtp.port,.approve_new]' "$CFG")" == "[\"$A\",\"local\",\"127.0.0.1\",587,true]" \
   && ${#PW} -ge 24 && "$(jq -r .agents.max.pass_sha256 "$W/etc/server.json")" == "$H" \
   && "$(jq -r .agents.max.maildir "$W/etc/server.json")" == "$W/spool/boxes/max" && -d "$W/spool/boxes/max/new" ]] \
  && ok "S2 self-hosted: max@<domain>, a fresh password whose hash is on the server, its own maildir" || bad "S2 self-hosted" "$RC $OUT $(cat "$CFG")"
[[ "$OUT" != *"$PW"* ]] && ok "S2b the new password is never printed" || bad "S2b printed"
[[ "$(jq -r .check_sender "$CFG")" == false ]] && ok "S2c connect keeps the sender-check switch" || bad "S2c keep check_sender" "$(cat "$CFG")"
run gate max sender on
run gate max spam off
[[ $RC == 0 && "$(jq -c '.agents.max | [.spam, .virus]' "$W/etc/server.json")" == '[false,null]' ]] && ok "G10 gate spam off: the server skips spam filtering for max only" || bad "G10 spam off" "$RC $OUT $(cat "$W/etc/server.json")"
run gate max virus off
OUT=$(FIVEDIVE_JSON_MODE=1 bash "$BIN" status max 2>&1)
[[ "$(jq -c '.data | [.sender_check,.spam_filter,.virus_scan]' <<<"$OUT")" == '["on","off","off"]' ]] && ok "G11 status --json carries the sender check and both filters" || bad "G11 status filters" "$OUT"
run gate max spam on; run gate max virus on
[[ "$(jq -c '.agents.max | [.spam, .virus]' "$W/etc/server.json")" == '[true,true]' ]] && ok "G12 gate spam/virus on again" || bad "G12 on" "$(cat "$W/etc/server.json")"
OUT=$(bash "$BIN" status max 2>&1)
[[ "$OUT" == *"sender:     checked"* && "$OUT" == *"viruses:    a mail with a virus is dropped"* ]] && ok "G13 status says what is checked, in plain words" || bad "G13 status words" "$OUT"

EMAIL_SEND_PROBE_HOSTS=$SHUT run server status
[[ "$OUT" == *"sending:    BLOCKED"*"--relay=resend"* ]] && ok "P9 server status shows sending BLOCKED and the fix" || bad "P9 status shut" "$RC $OUT"
EMAIL_SEND_PROBE_HOSTS=$OPEN run server status
[[ "$OUT" == *"sending:    ok"* ]] && ok "P9b server status shows sending ok when port 25 is open" || bad "P9b status open" "$RC $OUT"

echo "status, disconnect"
OUT=$(FIVEDIVE_JSON_MODE=1 bash "$BIN" status max 2>&1)
[[ "$(jq -c '.data | [.connected,.address,.mode,.gate,.inbound_gate,.held_inbound]' <<<"$OUT")" == "[true,\"$A\",\"local\",\"on\",\"on\",0]" ]] && ok "T1 status --json" || bad "T1 status" "$OUT"
[[ "$(jq -c '.data.allowed' <<<"$OUT")" == "$(jq -c '.allowed // []' "$CFG")" && "$(jq -r '.data.allowed | type' <<<"$OUT")" == array ]] \
  && ok "T1b status --json carries the owner's list (the app's settings screen shows it, DIVE-8404)" || bad "T1b allowed" "$OUT $(cat "$CFG")"
run disconnect max
[[ $RC == 0 && ! -e "$CFG" && ! -e "$W/conn/email-max.env" && "$(jq -c '.agents' "$W/etc/server.json")" == '{}' && "$(cat "$W/channels")" == telegram ]] \
  && ok "T2 disconnect: config, password and server entry gone; channel off" || bad "T2 disconnect" "$RC $OUT"
# DIVE-8404: an agent whose ONLY channel is email (grep -v finds nothing to keep).
echo email >"$W/channels"; mkdir -p "$(dirname "$CFG")"; echo '{"address":"x@example.com","mode":"imap","smtp":{}}' >"$CFG"
run disconnect max
[[ $RC == 0 && ! -e "$CFG" && "$(cat "$W/channels")" == none ]] \
  && ok "T3 disconnect works when email is the agent's only channel (channels=none)" || bad "T3 email-only disconnect" "$RC $OUT"

echo "$PASS passed, $FAIL failed"
(( FAIL == 0 ))
