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
# secrets are read from"). Neither value is printed, passed as an
# argument, or left on disk.
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
# Needs: op (signed in as a person allowed to manage Connect servers) and jq.
# If a step fails after the server is made, the server is removed again, so
# the same command can be run a second time.
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
    -h|--help) sed -n '3,43p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument $1 (see --help)" ;;
  esac
done

[ -n "$server" ] || die "--server is required"
[ ${#reads[@]} -gt 0 ] || die "--reads is required: the vault the cluster reads"
[ -n "$keep" ] || die "--keep-in is required: the vault the credentials are kept in"
[ -n "$item" ] || item="$server Connect credentials"

# A name is used in a reference (op://vault/item/field) and in a list, so
# it cannot hold what would end either early.
plain() {
  case "$2" in
    *"/"*|*","*|*$'\n'*|*$'\r'*|"") die "$1 \"$2\" cannot be empty or hold a slash, a comma or a line break" ;;
  esac
}
plain --server "$server"; plain --keep-in "$keep"; plain --item "$item"
for v in "${reads[@]}"; do
  plain --reads "$v"
  [ "$v" != "$keep" ] || die "--keep-in \"$keep\" is a vault the server reads: the cluster would hold the way to its own credentials"
done

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

# Everything below reads 1Password before it makes anything.
op whoami >/dev/null || die "not signed in to 1Password: run 'op signin' first"
servers_before=$(op connect server list --format json) ||
  die "could not list Connect servers. One is made by a person signed in (op signin) who may manage them; a service account or a Connect token cannot"
if jq -e --arg n "$server" 'any(.[]?; .name == $n)' >/dev/null <<<"$servers_before"; then
  die "a Connect server named \"$server\" is there already. Nothing was made. Its credentials cannot be read again: use another name, or remove it first if nothing uses it"
fi
op vault get "$keep" >/dev/null || die "--keep-in vault \"$keep\" is not there, or you cannot see it. It is not made for you: who can open it is yours to decide"
if op item get "$item" --vault "$keep" --format json >/dev/null 2>&1; then
  die "vault \"$keep\" already has an item \"$item\". Nothing was made, and nothing is written over: give another --item"
fi
missing=()
for v in "${reads[@]}"; do
  op vault get "$v" >/dev/null 2>&1 || missing+=("$v")
done
if [ ${#missing[@]} -gt 0 ] && [ $create -eq 0 ]; then
  die "no vault named: $(printf '"%s" ' "${missing[@]}"). Nothing was made. --create-vaults makes them"
fi

if [ $dry -eq 1 ]; then
  for v in ${missing[@]+"${missing[@]}"}; do echo "would make vault \"$v\""; done
  echo "would make Connect server \"$server\" reading: $(printf '"%s" ' "${reads[@]}")"
  echo "would make a read-only token for it${expires:+, good for $expires}"
  echo "would keep both in vault \"$keep\" as item \"$item\""
  echo "nothing was made (--dry-run)"
  exit 0
fi

work=$(mktemp -d)
made_id="" made=0 kept=0
finish() {
  code=$?
  rm -rf "$work"
  if [ $made -eq 1 ] && [ $kept -eq 0 ]; then
    # The credentials are gone with $work, so the server is of no use.
    if [ -n "$made_id" ] && op connect server delete "$made_id" >/dev/null 2>&1; then
      echo "1password-connect: failed before the credentials were kept; Connect server \"$server\" was removed again" >&2
    else
      echo "1password-connect: failed before the credentials were kept, and Connect server \"$server\" could not be removed: remove it in 1Password (its credentials are lost)" >&2
    fi
  fi
  exit $code
}
trap finish EXIT

for v in ${missing[@]+"${missing[@]}"}; do
  op vault create "$v" >/dev/null
  echo "made vault \"$v\""
done

# op writes 1password-credentials.json into the directory it is run in.
made=1
(cd "$work" && op connect server create "$server" --vaults "$(IFS=,; echo "${reads[*]}")" >/dev/null)
# Which one is it? The one the list has now and did not have before: a
# name alone could be another server's.
made_id=$(op connect server list --format json | jq -r --arg n "$server" --argjson before "$servers_before" \
  '[.[]? | select(.name == $n) | .id] - [$before[]?.id] | if length == 1 then .[0] else "" end') || made_id=""
jq -e . "$work/1password-credentials.json" >/dev/null 2>&1 || die "op made no credentials file that reads as JSON"

token_args=()
for v in "${reads[@]}"; do token_args+=(--vault "$v,r"); done
[ -z "$expires" ] || token_args+=(--expires-in "$expires")
op connect token create "$server cluster token" --server "$server" "${token_args[@]}" >"$work/token"
[ -s "$work/token" ] || die "op made no token"

# The item is given to op on its input, never as arguments: those show in
# a process list. The credentials are kept twice, as the JSON and as its
# base64, which is the form the Connect chart's Secret holds.
jq -n --rawfile creds "$work/1password-credentials.json" --rawfile token "$work/token" \
  --arg title "$item" --arg server "$server" --arg reads "$(printf '%s\n' "${reads[@]}")" '{
    title: $title, category: "SECURE_NOTE",
    fields: [
      {id: "notesPlain", type: "STRING", purpose: "NOTES", label: "notesPlain",
       value: ("The credentials file and access token of 1Password Connect server \"" + $server + "\". A cluster rebuild reads them from here; nothing else holds a copy.")},
      {label: "server", type: "STRING", value: $server},
      {label: "reads", type: "STRING", value: ($reads | rtrimstr("\n"))},
      {label: "credentials-json", type: "CONCEALED", value: $creds},
      {label: "credentials-base64", type: "CONCEALED", value: ($creds | @base64)},
      {label: "token", type: "CONCEALED", value: ($token | rtrimstr("\n"))}
    ]}' >"$work/item.json"
op item create --vault "$keep" - <"$work/item.json" >/dev/null
kept=1

# Read each back the way a rebuild will, and compare without showing it.
sum() { sha256sum | cut -d' ' -f1; }
same() { [ "$(op read --no-newline "op://$keep/$item/$1" | sum)" = "$2" ]; }
ok=1
same credentials-json "$(jq -j -n --rawfile c "$work/1password-credentials.json" '$c' | sum)" || ok=0
same credentials-base64 "$(jq -j -n --rawfile c "$work/1password-credentials.json" '$c | @base64' | sum)" || ok=0
same token "$(jq -j -n --rawfile t "$work/token" '$t | rtrimstr("\n")' | sum)" || ok=0
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
