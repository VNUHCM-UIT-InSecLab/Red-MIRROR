from __future__ import annotations

import os
import re


TARGET_URL_PATTERN = re.compile(r"https?://[^\s)>\]\"']+")


def load_runtime_target_url(project_root=None) -> str:
    del project_root
    return str(os.environ.get("PENTEST_TARGET_URL", "")).strip()


def append_runtime_target_url(init_description: str, target_url: str) -> str:
    if not target_url:
        return init_description
    if target_url in init_description:
        return init_description
    return (
        f"{init_description.rstrip()}\n\n"
        f"IMPORTANT: AUTHORITATIVE TARGET URL (copy this exact scheme, host, and port): {target_url}"
    )
