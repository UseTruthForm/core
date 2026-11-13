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
# server is removed again, so the same command can be run a second time.
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
    -h|--help) sed -n '3,48p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
case "$expires" in
  *[!0-9smhdw]*) die "--expires-in \"$expires\" is not a length of time as op takes it (90d, 12w)" ;;
esac

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
if jq -e --arg n "$server" 'any(.[]; (.name // "" | ascii_downcase) == ($n | ascii_downcase))' >/dev/null <<<"$servers_before"; then
  die "a Connect server named \"$server\" is there already. Nothing was made. Its credentials cannot be read again: use another name, or remove it first if nothing uses it"
fi

# A vault is found by its name or its id, and known from here by its id:
# two spellings of one vault are one vault.
vaults=$(listed vaults vault list)
vault_id() {
  jq -r --arg v "$1" '[.[] | select((.name // "" | ascii_downcase) == ($v | ascii_downcase) or .id == $v) | .id] | if length > 1 then "*" else (.[0] // "") end' <<<"$vaults"
}
keep_id=$(vault_id "$keep")
[ "$keep_id" != "*" ] || die "more than one vault is named \"$keep\": give --keep-in its id"
[ -n "$keep_id" ] || die "--keep-in vault \"$keep\" is not there, or you cannot see it. It is not made for you: who can open it is yours to decide"
missing=()
for v in "${reads[@]}"; do
  id=$(vault_id "$v")
  [ "$id" != "*" ] || die "more than one vault is named \"$v\": give --reads its id"
  [ "$id" != "$keep_id" ] || die "--keep-in \"$keep\" is a vault the server reads: the cluster would hold the way to its own credentials"
  [ -n "$id" ] || missing+=("$v")
done
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
  jq -e --arg t "$item" 'any(.[]; (.title // "" | ascii_downcase) == ($t | ascii_downcase))' >/dev/null <<<"$l" || return 1
}
there=0; item_there || there=$?
[ $there -ne 0 ] || die "vault \"$keep\" already has an item \"$item\". Nothing was made, and nothing is written over: give another --item"
[ $there -eq 1 ] || die "could not list the items of vault \"$keep\". Nothing was made"

work=$(mktemp -d)
trying=0 kept=0
made_vaults=()

# new_server is the id of the one server of the name that the list has now
# and did not have before; a name alone could be another server's.
new_server() {
  local now
  now=$(op connect server list --format json 2>/dev/null) || return 1
  [ -n "$now" ] || now='[]'
  jq -r --arg n "$server" --argjson before "$servers_before" \
    'if type != "array" then error("not a list") else ([.[] | select(.name == $n) | .id] - [$before[].id] | if length == 1 then .[0] else "" end) end' <<<"$now" 2>/dev/null
}

finish() {
  code=$?
  trap - EXIT
  rm -rf "$work"
  if [ $trying -eq 1 ] && [ $kept -eq 0 ]; then
    for v in ${made_vaults[@]+"${made_vaults[@]}"}; do
      echo "1password-connect: vault \"$v\" was made and is left as it is" >&2
    done
    there=0; item_there || there=$?
    id=$(new_server) || id=""
    if [ $there -ne 1 ]; then
      # op said the item was not saved, and it may have been all the same.
      echo "1password-connect: failed, and vault \"$keep\" may hold an item \"$item\" from this run. Nothing was removed: look at the item, and remove it and Connect server \"$server\" before you run this again" >&2
    elif [ -z "$id" ]; then
      echo "1password-connect: failed. No one new Connect server named \"$server\" is listed, so none was removed: if 1Password shows one, remove it (its credentials are lost)" >&2
    elif op connect server delete "$id" >/dev/null 2>&1; then
      echo "1password-connect: failed before the credentials were kept; Connect server \"$server\" was removed again" >&2
    else
      echo "1password-connect: failed before the credentials were kept, and Connect server \"$server\" could not be removed: remove it in 1Password (its credentials are lost)" >&2
    fi
  fi
  exit $code
}
trap finish EXIT

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
for v in ${missing[@]+"${missing[@]}"}; do
  op vault create "$v" >/dev/null
  made_vaults+=("$v")
  echo "made vault \"$v\""
done

# op writes 1password-credentials.json into the directory it is run in.
(cd "$work" && op connect server create "$server" --vaults "$(IFS=,; echo "${reads[*]}")" >/dev/null)
jq -e . "$work/1password-credentials.json" >/dev/null 2>&1 || die "op made no credentials file that reads as JSON"
# The token is asked for by the server's id where that is known.
made_id=$(new_server) || made_id=""

token_args=()
for v in "${reads[@]}"; do token_args+=(--vault "$v,r"); done
[ -z "$expires" ] || token_args+=(--expires-in "$expires")
op connect token create "$server cluster token" --server "${made_id:-$server}" "${token_args[@]}" >"$work/token"
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
[ $ok -eq 1 ] || die "item \"$item\" was made in vault \"$keep\", but what reads back from it is not what was saved. The server is left as it is: look at the item before you use it"

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
