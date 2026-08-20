#!/bin/sh
# Install the Ossprey plugin for Claude Code.
#
# Remote install:
#   curl -fsSL https://raw.githubusercontent.com/ossprey/claude-plugin/main/install.sh | sh
#
# Auth: run `ossprey login` once (browser sign-in, no key to manage), or pass
# --key YOUR_API_KEY for headless setups.
#
# From a checkout (installs that working tree, e.g. a feature branch):
#   sh install.sh
#
# Options:
#   -k, --key <key>      save an Ossprey API key to ~/.config/ossprey/env
#                        (read by the hooks, which pass it to the CLI);
#                        unnecessary after `ossprey login`
#   -b, --branch <ref>   add the marketplace at this branch or tag (remote
#                        mode)
#   --uninstall          remove the plugin and its marketplace
#   -h, --help           show this help
#
# This repository is both the plugin and its marketplace, so the installer
# just drives Claude Code's own plugin CLI:
#
#   claude plugin marketplace add ossprey/claude-plugin
#   claude plugin install ossprey@ossprey
#
# In a checkout, the marketplace is added from that directory instead, so the
# working tree you have (branch and all) is what gets installed. Claude Code
# picks the plugin up on the next session; run `/plugin` in a running session
# to see or toggle it.
#
# A local install also writes hooks/hooks.json from hooks/hooks.posix.json --
# the active wiring is always a copy of one of the two canonical files, so
# OSSPREY_HOOKS_STYLE=windows (install.ps1's default on Windows) is reversible
# by re-running this script.
set -u

REPO="${OSSPREY_PLUGIN_REPO:-ossprey/claude-plugin}"
MARKETPLACE="${OSSPREY_MARKETPLACE_NAME:-ossprey}"
PLUGIN="ossprey"
CLAUDE_BIN="${CLAUDE_BIN:-claude}"
MANIFEST=".claude-plugin/plugin.json"
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ossprey"
CONF="$CONF_DIR/env"
BRANCH=""
KEY_ARG=""
UNINSTALL=0

info() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
  awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0" 2>/dev/null
}

while [ $# -gt 0 ]; do
  case "$1" in
    -k|--key)
      [ $# -ge 2 ] || die "$1 needs a value"
      KEY_ARG="$2"; shift 2 ;;
    -b|--branch)
      [ $# -ge 2 ] || die "$1 needs a value"
      BRANCH="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

is_ossprey_plugin() { # is_ossprey_plugin <dir>
  [ -f "$1/$MANIFEST" ] && grep -q '"name"[[:space:]]*:[[:space:]]*"ossprey"' "$1/$MANIFEST"
}

saved_key() { # print the key stored in the config file, if any
  [ -f "$CONF" ] || return 0
  sed -n 's/^OSSPREY_API_KEY=//p' "$CONF" | tail -1
}

save_key() { # save_key <key> — upsert OSSPREY_API_KEY in the config file
  mkdir -p "$CONF_DIR" || die "cannot create $CONF_DIR"
  (
    umask 077
    { [ -f "$CONF" ] && grep -v '^OSSPREY_API_KEY=' "$CONF"
      printf 'OSSPREY_API_KEY=%s\n' "$1"
    } > "$CONF.tmp"
  ) || die "cannot write $CONF"
  mv "$CONF.tmp" "$CONF" && chmod 600 "$CONF" || die "cannot write $CONF"
  info "Saved API key to $CONF"
}

has_credentials() { # a stored `ossprey login` session or an API key
  [ -n "${OSSPREY_API_KEY:-}" ] && return 0
  [ -n "$(saved_key)" ] && return 0
  # `ossprey login` stores tokens in the CLI's config dir: OSSPREY_CONFIG_DIR
  # when set, else the platform user config dir.
  [ -n "${OSSPREY_CONFIG_DIR:-}" ] && [ -f "$OSSPREY_CONFIG_DIR/credentials.json" ] && return 0
  [ -f "$CONF_DIR/credentials.json" ] && return 0
  [ -f "$HOME/Library/Application Support/ossprey/credentials.json" ] && return 0
  return 1
}

have_claude() { command -v "$CLAUDE_BIN" >/dev/null 2>&1; }

set_hook_wiring() { # set_hook_wiring <checkout dir>
  # hooks/hooks.json is the active wiring, always written from one of the two
  # canonical files, so the choice is idempotent and reversible.
  style="${OSSPREY_HOOKS_STYLE:-posix}"
  case "$style" in
    windows) name=hooks.windows.json ;;
    *) name=hooks.posix.json ;;
  esac
  [ -f "$1/hooks/$name" ] || return 0
  cp "$1/hooks/$name" "$1/hooks/hooks.json" || die "cannot write $1/hooks/hooks.json"
}

if [ "$UNINSTALL" -eq 1 ]; then
  [ -z "$KEY_ARG" ] || die "--key cannot be combined with --uninstall"
  have_claude || die "the claude CLI is not on PATH; nothing to uninstall from."
  # Both steps are best-effort: either may already be gone.
  "$CLAUDE_BIN" plugin uninstall "$PLUGIN@$MARKETPLACE" 2>/dev/null \
    || info "Plugin $PLUGIN@$MARKETPLACE was not installed."
  "$CLAUDE_BIN" plugin marketplace remove "$MARKETPLACE" 2>/dev/null \
    || info "Marketplace $MARKETPLACE was not registered."
  info "Removed $PLUGIN@$MARKETPLACE. It unloads on the next Claude Code session."
  exit 0
fi

[ -z "$KEY_ARG" ] || save_key "$KEY_ARG"

# Local mode: if this script sits inside a plugin checkout, install that
# working tree (branch and all). $0 is not a file when piped via curl | sh.
SRC=""
case "$0" in
  *install.sh)
    SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
    if is_ossprey_plugin "$SCRIPT_DIR"; then
      SRC="$SCRIPT_DIR"
    fi ;;
esac

if [ -n "$SRC" ] && [ -n "$BRANCH" ]; then
  die "--branch only applies to remote installs; check out the branch in $SRC instead."
fi

have_claude || die "the claude CLI is required: https://code.claude.com/docs/en/quickstart
(then re-run this installer, or add the marketplace by hand with
'/plugin marketplace add $REPO' inside Claude Code)."

if [ -n "$SRC" ]; then
  set_hook_wiring "$SRC"
  SOURCE="$SRC"
else
  SOURCE="$REPO"
  [ -z "$BRANCH" ] || SOURCE="$REPO@$BRANCH"
fi

# `marketplace add` fails when the name is already registered; `update`
# refreshes it in place, which is also what re-running the installer means.
if "$CLAUDE_BIN" plugin marketplace add "$SOURCE" 2>/dev/null; then
  info "Added marketplace $SOURCE"
else
  "$CLAUDE_BIN" plugin marketplace update "$MARKETPLACE" >/dev/null 2>&1 \
    || die "could not add or update the marketplace $SOURCE.
Try it by hand: $CLAUDE_BIN plugin marketplace add $SOURCE"
  info "Updated marketplace $MARKETPLACE ($SOURCE)"
fi

"$CLAUDE_BIN" plugin install "$PLUGIN@$MARKETPLACE" --yes >/dev/null 2>&1 \
  || "$CLAUDE_BIN" plugin update "$PLUGIN@$MARKETPLACE" >/dev/null 2>&1 \
  || die "could not install $PLUGIN@$MARKETPLACE.
Try it by hand: $CLAUDE_BIN plugin install $PLUGIN@$MARKETPLACE"
info "Installed $PLUGIN@$MARKETPLACE"

if [ -n "$SRC" ]; then
  info "Installed from the local checkout $SRC."
  info "Re-run this script after local changes so Claude Code picks them up."
fi

info ""
info "Next steps:"
info "  1. Start a new Claude Code session (or run '/plugin' in a running one)
     so the plugin loads."
command -v "${OSSPREY_BIN:-ossprey}" >/dev/null 2>&1 \
  || info "  2. Install the Ossprey CLI (hooks fail open without it):
     curl -fsSL https://github.com/ossprey/ossprey-cli/releases/latest/download/install.sh | sudo sh"
if ! has_credentials; then
  info "  3. Sign in so the hooks can get malware verdicts:
     ossprey login
     (or re-run this installer with --key YOUR_API_KEY for headless setups;
     create a key at https://dashboard.ossprey.com)
     Without credentials the hooks fail open and nothing is checked for malware."
fi
