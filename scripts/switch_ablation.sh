#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 {baseline|no_rag|no_srmm|no_reflection|core_only|deepseek_full|deepseek_no_rag|deepseek_no_srmm|deepseek_no_reflection|deepseek_core_only}" >&2
  exit 1
fi

PROFILE="$1"
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

case "$PROFILE" in
  baseline) SRC="$ROOT_DIR/basic_config.baseline.yaml" ;;
  no_rag) SRC="$ROOT_DIR/basic_config.no_rag.yaml" ;;
  no_srmm) SRC="$ROOT_DIR/basic_config.no_srmm.yaml" ;;
  no_reflection) SRC="$ROOT_DIR/basic_config.no_reflection.yaml" ;;
  core_only) SRC="$ROOT_DIR/basic_config.core_only.yaml" ;;
  deepseek_full) SRC="$ROOT_DIR/basic_config.baseline.yaml" ;;
  deepseek_no_rag) SRC="$ROOT_DIR/basic_config.no_rag.yaml" ;;
  deepseek_no_srmm) SRC="$ROOT_DIR/basic_config.no_srmm.yaml" ;;
  deepseek_no_reflection) SRC="$ROOT_DIR/basic_config.no_reflection.yaml" ;;
  deepseek_core_only) SRC="$ROOT_DIR/basic_config.core_only.yaml" ;;
  *)
    echo "Unknown profile: $PROFILE" >&2
    echo "Valid profiles: baseline, no_rag, no_srmm, no_reflection, core_only, deepseek_full, deepseek_no_rag, deepseek_no_srmm, deepseek_no_reflection, deepseek_core_only" >&2
    exit 1
    ;;
esac

DEST="$ROOT_DIR/basic_config.yaml"
cp "$SRC" "$DEST"
echo "Switched basic_config.yaml -> $(basename "$SRC")"
