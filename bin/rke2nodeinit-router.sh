#!/usr/bin/env bash
# Kind/action routing helpers for rke2nodeinit.

set -Eeuo pipefail

rke2nodeinit_router_normalize_kind() {
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]_-'
}

rke2nodeinit_router_kind_to_action() {
  case "$(rke2nodeinit_router_normalize_kind "${1:-}")" in
    push) echo push ;;
    image|singlenodeimage) echo image ;;
    server|singlenodeserver) echo server ;;
    addserver) echo add-server ;;
    agent) echo agent ;;
    verify) echo verify ;;
    airgap) echo airgap ;;
    customca) echo custom-ca ;;
    *) return 1 ;;
  esac
}

rke2nodeinit_router_kind_is_single_node() {
  case "$(rke2nodeinit_router_normalize_kind "${1:-}")" in
    singlenodeimage|singlenodeserver) return 0 ;;
    *) return 1 ;;
  esac
}

rke2nodeinit_router_is_action() {
  case "${1:-}" in
    push|image|server|add-server|agent|verify|airgap|label-node|taint-node|custom-ca) return 0 ;;
    *) return 1 ;;
  esac
}
