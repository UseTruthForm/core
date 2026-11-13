#!/usr/bin/env bash
#
# Give a new environment its own 1Password Connect server, and keep what
# that makes where a rebuild can read it.
#
# A cluster that reads its Secrets from 1Password through Connect starts
# from two things only a person signed in to 1Password can make: the
# server's credentials file and an access token. This makes both for one
# environment, saves them as one item in a vault you name, and prints the
# references a secret sources file needs (docs/guide.md, "Where the
# secrets are read from"). Neither value is printed or passed as an
# argument; while it runs they are in a directory only you can read, which
# is removed when it ends.
#
# If it is stopped by a signal it removes its directory, and says what it
# made and left. Killed outright (kill -9) it can do neither: the
# directory under ${TMPDIR:-/tmp} then still holds the credentials file
# and the token, and the server may be there; remove both.
#
# It has been tried against a stand-in for op, and with --dry-run against
# a real account. It has not yet made a server on a real account: run it
# with --dry-run first, and read what it says it made.
#
# It is run once for each new environment. A rebuild of an environment
# that has had it run needs nothing made: the credentials are 1Password's
# and not the cluster's, so the ones kept still work.
#
#   op signin
#   examples/bootstrap/1password-connect.sh \
#     --server test-cluster --reads "App Config Test" --keep-in "Break Glass" \
#     --credentials-secret onepassword/op-credentials \
#     --token-secret onepassword/onepassword-token
#
# Names (server, vaults, item) hold letters, digits, spaces, dots, dashes
# and underscores, and start with a letter or digit: that is what a
# 1Password reference can name.
#
#   --server <name>     the Connect server to make; refused if one has the name
#   --reads <vault>     a vault the server and its token may read (repeatable).
#                       The token is read-only.
#   --keep-in <vault>   the vault the credentials are kept in. It has to be
#                       there already, and cannot be one the server reads:
#                       the cluster would then hold the way to its own keys.
#   --item <title>      the item's title (default "<server> Connect credentials");
#                       refused if the vault has one of that title
#   --create-vaults     make a --reads vault that is not there
#   --expires-in <d>    how long the token is good for (as op takes it: 90d);
#                       default: it does not expire
#   --credentials-secret <namespace>/<name>[:<key>]
#   --token-secret <namespace>/<name>[:<key>]
#                       print the sources-file entries for these Secrets too
#                       (keys default to 1password-credentials.json and token)
#   --dry-run           check everything, and make nothing
#
# Needs: op (signed in as a person allowed to manage Connect servers), jq
# (1.6 or later) and cmp. If a step fails after the server is made, the
# server is removed again, so the same command can be run a second time;
# a signal ends it the same way, and the cleaning up is not interrupted.
set -euo pipefail
umask 077

server="" keep="" item="" expires="" credsec="" toksec="" create=0 dry=0
reads=()

die() { echo "1password-connect: $*" >&2; exit 1; }
need() { [ $# -ge 2 ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) need "$@"; server=$2; shift 2 ;;
    --reads) need "$@"; reads+=("$2"); shift 2 ;;
    --keep-in) need "$@"; keep=$2; shift 2 ;;
    --item) need "$@"; item=$2; shift 2 ;;
    --expires-in) need "$@"; expires=$2; shift 2 ;;
    --credentials-secret) need "$@"; credsec=$2; shift 2 ;;
    --token-secret) need "$@"; toksec=$2; shift 2 ;;
    --create-vaults) create=1; shift ;;
    --dry-run) dry=1; shift ;;
    -h|--help) sed -n '3,49p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
done

[ -n "$server" ] || die "--server is required"
[ ${#reads[@]} -gt 0 ] || die "--reads is required: the vault the cluster reads"
[ -n "$keep" ] || die "--keep-in is required: the vault the credentials are kept in"
[ -n "$item" ] || item="$server Connect credentials"

# A name is used in a reference (op://vault/item/field), which can name
# only these; anything else would be made and then not found again.
plain() {
  case "$2" in
    ""|[!A-Za-z0-9]*|*[!A-Za-z0-9\ ._-]*) die "$1 \"$2\": a name holds letters, digits, spaces, dots, dashes and underscores, and starts with a letter or digit" ;;
  esac
}
plain --server "$server"; plain --keep-in "$keep"; plain --item "$item"
for v in "${reads[@]}"; do plain --reads "$v"; done
# A length of time is checked here, with everything else: op would refuse
# a bad one only after the server was made.
if [ -n "$expires" ] && ! [[ "$expires" =~ ^([0-9]+[smhdw])+$ ]]; then
  die "--expires-in \"$expires\" is not a length of time as op takes it (90d, 12w, 1d12h)"
fi

# A Secret is named namespace/name, with the key after a colon.
secret_of() { printf '%s' "${1%%:*}"; }
key_of() { case "$1" in *:*) printf '%s' "${1#*:}" ;; *) printf '%s' "$2" ;; esac; }
for s in "$credsec" "$toksec"; do
  [ -z "$s" ] && continue
  case "$(secret_of "$s")" in
    */*/*|/*|*/|*[!A-Za-z0-9./-]*) die "a Secret is given as <namespace>/<name>[:<key>], not \"$s\"" ;;
    */*) ;;
    *) die "a Secret is given as <namespace>/<name>[:<key>], not \"$s\"" ;;
  esac
  case "$(key_of "$s" k)" in
    *[!A-Za-z0-9._-]*|"") die "a Secret's key holds letters, digits, dots, dashes and underscores, not \"$s\"" ;;
  esac
done

command -v op >/dev/null || die "the 1Password CLI (op) is not installed"
command -v jq >/dev/null || die "jq is not installed"
command -v cmp >/dev/null || die "cmp is not installed"
jq -n --rawfile x /dev/null '$x' >/dev/null 2>&1 || die "jq 1.6 or later is needed (this one has no --rawfile)"

# named: is an entry of a JSON list called this (by the field given, any
# case)? 0 yes, 1 no. A list jq cannot read that way stops the script:
# "could not tell" is never taken as "not there".
named() { # <list> <field> <name> <what>
  local rc=0
  jq -e --arg f "$2" --arg n "$3" 'any(.[]; (.[$f] // "" | tostring | ascii_downcase) == ($n | ascii_downcase))' >/dev/null 2>&1 <<<"$1" || rc=$?
  [ $rc -le 1 ] || die "op's list of $4 could not be read for names: this script does not know this version of op. Nothing was made"
  return $rc
}

# Everything below reads 1Password before it makes anything. A list that
# does not read as one stops it: nothing is taken as absent because a
# question went unanswered.
listed() { # <what> <op arguments...>: a JSON list, or the end
  local what=$1 out; shift
  out=$(op "$@" --format json) || die "could not list $what${hint:+. $hint}"
  [ -n "$out" ] || out='[]'
  jq -e 'type == "array"' >/dev/null 2>&1 <<<"$out" || die "op's list of $what does not read as a list: this script does not know this version of op"
  printf '%s' "$out"
}
# Not "op whoami": signed in through the 1Password app, it says "not signed
# in" where every other command works. The first list is the test.
hint="Sign in first (op signin, or the 1Password app's CLI integration). One is made by a person who may manage them; a service account or a Connect token cannot"
servers_before=$(listed "Connect servers" connect server list)
hint=""
if named "$servers_before" name "$server" "Connect servers"; then
  die "a Connect server named \"$server\" is there already. Nothing was made. Its credentials cannot be read again: use another name, or remove it first if nothing uses it"
fi

# A vault is found by its name or its id, and known from here by its id:
# two spellings of one vault are one vault.
vaults=$(listed vaults vault list)
vault_id() {
  jq -r --arg v "$1" '[.[] | select((.name // "" | tostring | ascii_downcase) == ($v | ascii_downcase) or .id == $v) | .id | tostring] | if length > 1 then "*" else (.[0] // "") end' <<<"$vaults" ||
    die "op's list of vaults could not be read for names: this script does not know this version of op. Nothing was made"
}
keep_id=$(vault_id "$keep")
[ "$keep_id" != "*" ] || die "more than one vault is named \"$keep\": give --keep-in its id"
[ -n "$keep_id" ] || die "--keep-in vault \"$keep\" is not there, or you cannot see it. It is not made for you: who can open it is yours to decide"
# One vault given twice (by another spelling, or by its id) is one vault.
# read_refs is how each is given to op: by its id where it is there, which
# is exact, and by its name where it is still to be made.
missing=() read_refs=() read_names=() to_make=()
seen=","
for v in "${reads[@]}"; do
  id=$(vault_id "$v")
  [ "$id" != "*" ] || die "more than one vault is named \"$v\": give --reads its id"
  [ "$id" != "$keep_id" ] || die "--keep-in \"$keep\" is a vault the server reads: the cluster would hold the way to its own credentials"
  key=${id:-name:$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')}
  case "$seen" in *",$key,"*) continue ;; esac
  seen="$seen$key,"
  read_names+=("$v")
  if [ -n "$id" ]; then read_refs+=("$id"); to_make+=(0); else read_refs+=("$v"); to_make+=(1); missing+=("$v"); fi
done
reads=("${read_names[@]}")
if [ ${#missing[@]} -gt 0 ] && [ $create -eq 0 ]; then
  die "no vault named: $(printf '"%s" ' "${missing[@]}"). Nothing was made. --create-vaults makes them"
fi

# item_there: 0 if the vault has an item of the title, 1 if not, 2 if that
# cannot be told.
item_there() {
  local l
  l=$(op item list --vault "$keep_id" --format json 2>/dev/null) || return 2
  [ -n "$l" ] || l='[]'
  jq -e 'type == "array"' >/dev/null 2>&1 <<<"$l" || return 2
  local rc=0
  jq -e --arg t "$item" 'any(.[]; (.title // "" | tostring | ascii_downcase) == ($t | ascii_downcase))' >/dev/null 2>&1 <<<"$l" || rc=$?
  [ $rc -le 1 ] || return 2
  return $rc
}
there=0; item_there || there=$?
[ $there -ne 0 ] || die "vault \"$keep\" already has an item \"$item\". Nothing was made, and nothing is written over: give another --item"
[ $there -eq 1 ] || die "could not list the items of vault \"$keep\". Nothing was made"

work=$(mktemp -d)
trying=0 server_tried=0 kept=0 done_all=0 said_kept=0 making_vault="" create_words=""
made_vaults=()

# made_server is the id of the server this run made: one that op printed
# when this run asked for the server, that the list has now under the
# name, and that it did not have before. A server that is only new and of
# the name could be someone else's, made in the same moment; one op did
# not print for this run is never taken to be this run's.
made_server() {
  local now
  [ -n "$create_words" ] || return 1
  now=$(op connect server list --format json 2>/dev/null) || return 1
  [ -n "$now" ] || now='[]'
  jq -r --arg n "$server" --argjson before "$servers_before" --arg said "$create_words" \
    'if type != "array" then error("not a list") else
       ($said | split("\n")) as $words
       | ([.[] | select(.name == $n and (.id | type) == "string" and .id != "") | .id] - [$before[]? | .id?]
          | map(select(. as $id | $words | index($id) != null)) | unique
          | if length == 1 then .[0] else "" end) end' <<<"$now" 2>/dev/null
}

finish() {
  code=$?
  # Nothing interrupts the cleaning up: a second signal would leave the
  # credentials file and the server behind with no word of it.
  trap '' INT TERM HUP
  trap - EXIT
  set +e
  rm -rf "$work" || echo "1password-connect: could not remove $work, which may hold the credentials: remove it" >&2
  for v in ${made_vaults[@]+"${made_vaults[@]}"}; do
    [ $kept -eq 1 ] || echo "1password-connect: vault \"$v\" was made and is left as it is" >&2
  done
  # Stopped while a vault was being made: it may be there.
  [ -z "$making_vault" ] || echo "1password-connect: stopped while vault \"$making_vault\" was being made: it may be there, and is left as it is" >&2
  # Stopped after the item was saved and before it was read back: both
  # are there, and nobody has checked that the item reads as it should.
  if [ $kept -eq 1 ] && [ $done_all -eq 0 ] && [ $code -ne 0 ] && [ $said_kept -eq 0 ]; then
    echo "1password-connect: stopped after Connect server \"$server\" was made and item \"$item\" was saved in vault \"$keep\", and before the item was read back. Both are left as they are: read the item (op read \"op://$keep/$item/token\") before you use it, or remove both and run this again" >&2
  fi
  # Only once this run asked for a server: before that, a new server of
  # the name is someone else's.
  if [ $server_tried -eq 1 ] && [ $kept -eq 0 ]; then
    there=0; item_there || there=$?
    id=$(made_server) || id=""
    if [ $there -ne 1 ]; then
      # op said the item was not saved, and it may have been all the same.
      echo "1password-connect: failed, and vault \"$keep\" may hold an item \"$item\" from this run. Nothing was removed: look at the item, and remove it and Connect server \"$server\" before you run this again" >&2
    elif [ -z "$id" ]; then
      echo "1password-connect: failed. No Connect server named \"$server\" is listed that op said this run made, so none was removed: if 1Password shows one that is yours, remove it (its credentials are lost)" >&2
    elif op connect server delete "$id" >/dev/null 2>&1; then
      echo "1password-connect: failed before the credentials were kept; Connect server \"$server\" was removed again" >&2
    else
      echo "1password-connect: failed before the credentials were kept, and Connect server \"$server\" could not be removed: remove it in 1Password (its credentials are lost)" >&2
    fi
  fi
  exit $code
}
trap finish EXIT
# A signal ends the script by way of finish, with the usual exit code.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# The item is given to op as a file in the private directory, never as
# arguments: those show in a process list. (As a file named with
# --template: op reads a template on its input only from a pipe, and with
# --category it drops the template's fields.) The credentials are kept twice, as the JSON and as its
# base64, which is the form the Connect chart's Secret holds.
item_of() { # <credentials file> <token file>
  jq -n --rawfile creds "$1" --rawfile token "$2" \
    --arg title "$item" --arg server "$server" --arg reads "$(printf '%s\n' "${reads[@]}")" '{
      title: $title, category: "SECURE_NOTE",
      fields: [
        {id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain",
         value: ("The credentials file and access token of 1Password Connect server \"" + $server + "\". A cluster rebuild reads them from here; nothing else holds a copy.")},
        {label: "server", type: "STRING", value: $server},
        {label: "reads", type: "STRING", value: ($reads | rtrimstr("\n"))},
        {label: "credentials-json", type: "CONCEALED", value: ($creds | rtrimstr("\n"))},
        {label: "credentials-base64", type: "CONCEALED", value: ($creds | @base64)},
        {label: "token", type: "CONCEALED", value: ($token | rtrimstr("\n"))}
      ]}'
}

# Would op take the item? Asked with made-up values, before there is a
# server whose credentials depend on the answer.
echo '{"made":"up"}' >"$work/try-creds"; echo made-up >"$work/try-token"
item_of "$work/try-creds" "$work/try-token" >"$work/try.json"
# What it says it would save is read too: the title and the three fields
# are how the credentials are found again.
op item create --vault "$keep_id" --template "$work/try.json" --dry-run --format json >"$work/try-out.json" ||
  die "op would not save the item this makes in vault \"$keep\". Nothing was made"
jq -e --arg t "$item" '.title == $t and ([.fields[]?.label] | index("credentials-json") != null and index("credentials-base64") != null and index("token") != null)' \
  "$work/try-out.json" >/dev/null 2>&1 ||
  die "op would save the item, but not under its title with the fields the credentials are read back from: this script does not know this version of op. Nothing was made"

if [ $dry -eq 1 ]; then
  for v in ${missing[@]+"${missing[@]}"}; do echo "would make vault \"$v\""; done
  echo "would make Connect server \"$server\" reading: $(printf '"%s" ' "${reads[@]}")"
  echo "would make a read-only token for it${expires:+, good for $expires}"
  echo "would keep both in vault \"$keep\" as item \"$item\""
  echo "nothing was made (--dry-run)"
  exit 0
fi

trying=1
for i in "${!read_refs[@]}"; do
  v=${read_refs[$i]}
  [ "${to_make[$i]}" -eq 1 ] || continue
  # Known by its id from here, as the others are.
  making_vault=$v
  made=$(op vault create "$v" --format json) || { making_vault=""; die "could not make vault \"$v\""; }
  made_vaults+=("$v"); making_vault=""
  id=$(jq -r '.id // empty | tostring' 2>/dev/null <<<"$made") || id=""
  [ -z "$id" ] || read_refs[$i]=$id
  echo "made vault \"$v\""
done

# The servers as they are now, read again: one that appeared since this
# started is not this run's. From here a new server of the name is.
servers_before=$(listed "Connect servers" connect server list)
if named "$servers_before" name "$server" "Connect servers"; then
  die "a Connect server named \"$server\" was made by someone else while this ran. No server was made"
fi
server_tried=1
# op writes 1password-credentials.json into the directory it is run in.
# What op prints is kept for the id of the server it made, as words (an
# id is no secret; the rest is not shown): that id is how this run knows
# its own server, in the cleaning up too.
create_words=$(cd "$work" && op connect server create "$server" --vaults "$(IFS=,; echo "${read_refs[*]}")" | tr -cs 'A-Za-z0-9_-' '\n')
jq -e . "$work/1password-credentials.json" >/dev/null 2>&1 || die "op made no credentials file that reads as JSON"
# The token is asked for by that id, never by the name: another server
# may have the name by now.
made_id=$(made_server) || made_id=""
[ -n "$made_id" ] || die "op made a Connect server and did not say which: no id it printed is listed under \"$server\", so no token was asked for"

token_args=()
for v in "${read_refs[@]}"; do token_args+=(--vault "$v,r"); done
[ -z "$expires" ] || token_args+=(--expires-in "$expires")
op connect token create "$server cluster token" --server "$made_id" "${token_args[@]}" >"$work/token"
[ -s "$work/token" ] || die "op made no token"

item_of "$work/1password-credentials.json" "$work/token" >"$work/item.json"
op item create --vault "$keep_id" --template "$work/item.json" >/dev/null
kept=1

# Read each back the way a rebuild will, and compare without showing it.
ok=1
for f in credentials-json credentials-base64 token; do
  jq -j --arg f "$f" '.fields[] | select(.label == $f) | .value' "$work/item.json" >"$work/want"
  op read --no-newline "op://$keep/$item/$f" 2>/dev/null | cmp -s - "$work/want" || ok=0
done
[ $ok -eq 1 ] || { said_kept=1; die "item \"$item\" was made in vault \"$keep\", but what reads back from it is not what was saved. The server is left as it is: look at the item before you use it"; }
done_all=1

echo "made Connect server \"$server\" and a read-only token; both read: $(printf '"%s" ' "${reads[@]}")"
echo "kept in vault \"$keep\" as item \"$item\", and read back from it (no value was printed)"
echo
echo "references for a secret sources file:"
echo "  credentials file, base64 (what the Connect chart's Secret holds): op://$keep/$item/credentials-base64"
echo "  credentials file, as JSON:                                        op://$keep/$item/credentials-json"
echo "  access token:                                                     op://$keep/$item/token"
if [ -n "$credsec$toksec" ]; then
  echo
  echo "entries for it:"
  if [ -n "$credsec" ]; then
    printf '  - secret: %s\n    from:\n      %s: "op://%s/%s/credentials-base64"\n' "$(secret_of "$credsec")" "$(key_of "$credsec" 1password-credentials.json)" "$keep" "$item"
  fi
  if [ -n "$toksec" ]; then
    printf '  - secret: %s\n    from:\n      %s: "op://%s/%s/token"\n' "$(secret_of "$toksec")" "$(key_of "$toksec" token)" "$keep" "$item"
  fi
fi
