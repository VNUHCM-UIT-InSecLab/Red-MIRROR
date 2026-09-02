#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


BENCHMARK_ROOT = Path(__file__).resolve().parents[1]
RED_MIRROR_REPO_ROOT = BENCHMARK_ROOT.parents[1]
DEFAULT_VULNBOT_ROOT = RED_MIRROR_REPO_ROOT / "VulnBot"
DEFAULT_PROMPT_CSV = BENCHMARK_ROOT / "prompt.csv"
DEFAULT_RESET_SCRIPT = BENCHMARK_ROOT / "scripts" / "reset_docker_up.sh"
DEFAULT_VULNBOT_CLI = DEFAULT_VULNBOT_ROOT / "cli.py"
RUNS_DIR = BENCHMARK_ROOT / ".runtime" / "experiments" / "vulnbot"
FLAG_PATTERN = re.compile(r"FLAG\{[^}\s]+\}", re.IGNORECASE)


@dataclass
class RunResult:
    task: str
    status: str
    target_url: str = ""
    reset_seconds: float = 0.0
    pentest_seconds: float = 0.0
    reset_exit_code: int = 0
    pentest_exit_code: int = 0
    error: str = ""
    autopentest_log: str = ""


def wall_clock_stamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _python_can_import_click(python_cmd: str) -> bool:
    try:
        result = subprocess.run(
            [python_cmd, "-c", "import click"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def default_python_command(vulnbot_root: Path) -> str:
    candidates = [
        vulnbot_root / "venv" / "bin" / "python",
        vulnbot_root / "venv" / "Scripts" / "python.exe",
    ]
    for candidate in candidates:
        if candidate.exists() and _python_can_import_click(str(candidate)):
            return str(candidate)
    for candidate in [sys.executable, "python3"]:
        if candidate and _python_can_import_click(str(candidate)):
            return str(candidate)
    return sys.executable or "python3"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run VulnBot on benchmark tasks with the same reset/prompt flow as Red-MIRROR."
    )
    parser.add_argument("tasks", nargs="*", help="Task IDs to run. Defaults to all rows in prompt.csv.")
    parser.add_argument("--file", help="Text file with task IDs, one per line.")
    parser.add_argument("--prompt-csv", default=str(DEFAULT_PROMPT_CSV), help="Path to prompt.csv.")
    parser.add_argument("--reset-script", default=str(DEFAULT_RESET_SCRIPT), help="Path to reset_docker_up.sh.")
    parser.add_argument("--vulnbot-root", default=str(DEFAULT_VULNBOT_ROOT), help="Path to VulnBot repo.")
    parser.add_argument("--cli-script", default=str(DEFAULT_VULNBOT_CLI), help="Path to VulnBot cli.py.")
    parser.add_argument("--experiment-name", default="default", help="Experiment folder name under .runtime/experiments/vulnbot.")
    parser.add_argument("--run-id", default="", help="Run folder name. Defaults to timestamp.")
    parser.add_argument("--python", default="", help="Python command for VulnBot cli.py.")
    parser.add_argument("-m", "--max-interactions", type=int, default=5, help="Value passed to cli.py vulnbot -m.")
    parser.add_argument("--reset-timeout", type=int, default=900, help="Timeout seconds for reset_docker_up.sh.")
    parser.add_argument("--pentest-timeout", type=int, default=900, help="Timeout seconds for each VulnBot challenge.")
    parser.add_argument("--continue-on-failure", action="store_true", help="Continue after a failed challenge.")
    parser.add_argument("--image-prune", action="store_true", help="Allow reset_docker_up.sh to prune Docker images.")
    parser.add_argument("--skip-empty-prompt", action="store_true", help="Skip tasks with empty prompt.csv prompt.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without running them.")
    parser.add_argument("--verify-prompt-flow", action="store_true", help="Print final init_description and exit before agents run.")
    return parser.parse_args()


def normalize_task(task: str) -> str:
    task = task.strip()
    if not task:
        return ""
    if task.startswith(("XBEN-", "CVE-")):
        return task
    return f"CVE-{task}"


def load_prompt_table(path: Path) -> tuple[list[str], dict[str, str]]:
    rows = list(csv.reader(path.read_text(encoding="utf-8-sig").splitlines()))
    if not rows:
        raise ValueError(f"empty prompt CSV: {path}")
    order: list[str] = []
    prompts: dict[str, str] = {}
    for row in rows[1:]:
        if not row:
            continue
        task = normalize_task(row[0])
        if not task:
            continue
        prompt = row[-1].strip() if len(row) >= 2 else ""
        order.append(task)
        prompts[task] = prompt
    return order, prompts


def read_task_file(path: Path) -> list[str]:
    tasks: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        item = line.split("#", 1)[0].strip()
        if item:
            tasks.append(normalize_task(item))
    return tasks


def select_tasks(args: argparse.Namespace, csv_order: list[str]) -> list[str]:
    selected = [normalize_task(task) for task in args.tasks if normalize_task(task)]
    if args.file:
        selected.extend(read_task_file(Path(args.file)))
    if not selected:
        selected = list(csv_order)
    deduped: list[str] = []
    seen: set[str] = set()
    for task in selected:
        if task and task not in seen:
            seen.add(task)
            deduped.append(task)
    return deduped


def run_logged(
    command: list[str],
    cwd: Path,
    log_path: Path | None,
    timeout: int = 0,
    env: dict[str, str] | None = None,
) -> tuple[int, float, str]:
    def _terminate_process_tree(proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        try:
            if os.name == "nt":
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                    return
                except subprocess.TimeoutExpired:
                    proc.kill()
                    return
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
                return
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            return
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    started = time.monotonic()
    captured_chunks: list[str] = []
    log_handle = None
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = log_path.open("w", encoding="utf-8", errors="replace")
        log_handle.write(f"$ {' '.join(command)}\n\n")
        log_handle.flush()
    try:
        proc = subprocess.Popen(
            command,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=None,
            bufsize=1,
            env=env,
            start_new_session=(os.name != "nt"),
        )
        assert proc.stdout is not None
        code = 0
        timed_out = False
        while True:
            if timeout > 0 and (time.monotonic() - started) >= timeout:
                _terminate_process_tree(proc)
                timed_out = True
                code = 124
                break

            ready, _, _ = select.select([proc.stdout], [], [], 0.2)
            if ready:
                line = proc.stdout.readline()
                if line:
                    print(line, end="")
                    captured_chunks.append(line)
                    if log_handle is not None:
                        log_handle.write(line)
                        log_handle.flush()
                    continue

            polled = proc.poll()
            if polled is not None:
                code = polled
                while True:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    print(line, end="")
                    captured_chunks.append(line)
                    if log_handle is not None:
                        log_handle.write(line)
                        log_handle.flush()
                break

        if timed_out:
            message = f"\n[TIMEOUT] after {timeout}s\n"
            print(message, end="")
            if log_handle is not None:
                log_handle.write(message)
                log_handle.flush()
        return code, time.monotonic() - started, "".join(captured_chunks)
    finally:
        if log_handle is not None:
            log_handle.close()


def extract_target_url_from_output(output: str) -> str:
    for line in (output or "").splitlines():
        if line.startswith("TARGET_URL="):
            return line.split("=", 1)[1].strip()
    return ""


def write_challenge_metadata(
    task_dir: Path,
    *,
    experiment_name: str,
    run_id: str,
    challenge_name: str,
    time_start: str,
    time_end: str,
    exploit_status: str,
) -> None:
    payload = {
        "experiment_name": experiment_name,
        "run_id": run_id,
        "challenge_name": challenge_name,
        "time_start": time_start,
        "time_end": time_end,
        "exploit_status": exploit_status,
    }
    (task_dir / "metadata.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    prune_challenge_output(task_dir)


def prune_challenge_output(task_dir: Path) -> None:
    """Keep only the benchmark log and metadata in a completed task directory."""
    keep = {"Autopentest.log", "metadata.json"}
    for path in task_dir.iterdir():
        if path.name in keep:
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)


def evaluate_exploit_status(task: str, pentest_code: int, autopentest_log: Path) -> tuple[str, str]:
    try:
        log_text = autopentest_log.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return "failed", f"could not read log: {exc}"

    if pentest_code == 124:
        if task.startswith("XBEN-") and FLAG_PATTERN.search(log_text):
            return "success", ""
        return "failed", "timed out without detected flag"
    if pentest_code != 0:
        return "failed", f"pentest exited {pentest_code}"
    if task.startswith("XBEN-") and not FLAG_PATTERN.search(log_text):
        return "failed", "XBEN flag was not found in Autopentest.log"
    return "success", ""


def build_run_dir(experiment_name: str, run_id: str) -> tuple[Path, str]:
    resolved_run_id = run_id or time.strftime("run_%Y%m%d-%H%M%S")
    return RUNS_DIR / experiment_name / resolved_run_id, resolved_run_id


def main() -> int:
    args = parse_args()
    prompt_csv = Path(args.prompt_csv)
    reset_script = Path(args.reset_script)
    vulnbot_root = Path(args.vulnbot_root)
    cli_script = Path(args.cli_script)
    python_command = shlex.split(args.python) if args.python else shlex.split(default_python_command(vulnbot_root))

    csv_order, prompts = load_prompt_table(prompt_csv)
    tasks = select_tasks(args, csv_order)
    if not tasks:
        print("No tasks selected.", file=sys.stderr)
        return 2

    missing = [task for task in tasks if task not in prompts]
    if missing:
        print(f"Tasks missing from prompt.csv: {', '.join(missing)}", file=sys.stderr)
        return 2

    run_dir, resolved_run_id = build_run_dir(args.experiment_name, args.run_id)

    print(f"[START_TIME] {wall_clock_stamp()}")
    print(f"[RUN_DIR] {run_dir}")
    print(f"[PLAN] {len(tasks)} tasks, timeout={args.pentest_timeout}s each")

    if args.dry_run:
        for task in tasks:
            task_dir = run_dir / task
            autopentest_log = task_dir / "Autopentest.log"
            reset_command = [str(reset_script), task]
            if not args.image_prune:
                reset_command.append("--no-image-prune")
            pentest_command = [
                *python_command,
                str(cli_script),
                "vulnbot",
                "-m",
                str(args.max_interactions),
                "--no-preload",
                "--no-save",
                "--task-prompt",
                "<prompt>",
            ]
            if args.verify_prompt_flow:
                pentest_command.append("--print-init-description")
            print("[DRY-RUN RESET]", " ".join(reset_command))
            print(f"[DRY-RUN LOG] {autopentest_log}")
            print("[DRY-RUN PENTEST]", " ".join(pentest_command))
        return 0

    run_dir.mkdir(parents=True, exist_ok=True)

    results: list[RunResult] = []
    exit_code = 0

    for index, task in enumerate(tasks, start=1):
        task_started_wall = wall_clock_stamp()
        print(f"\n[{index}/{len(tasks)}] {task}")
        task_prompt = prompts.get(task, "")
        task_dir = run_dir / task
        task_dir.mkdir(parents=True, exist_ok=True)
        autopentest_log = task_dir / "Autopentest.log"
        autopentest_log.touch(exist_ok=True)

        if not task_prompt:
            write_challenge_metadata(
                task_dir,
                experiment_name=args.experiment_name,
                run_id=resolved_run_id,
                challenge_name=task,
                time_start=task_started_wall,
                time_end=wall_clock_stamp(),
                exploit_status="failed",
            )
            print(f"[SKIP] {task}: empty prompt")
            if not args.skip_empty_prompt:
                exit_code = 1
                if not args.continue_on_failure:
                    break
            continue

        reset_command = [str(reset_script), task]
        if not args.image_prune:
            reset_command.append("--no-image-prune")
        print("[RESET]", " ".join(reset_command))
        reset_code, reset_seconds, reset_output = run_logged(
            reset_command,
            RED_MIRROR_REPO_ROOT,
            task_dir / "reset.log",
            timeout=args.reset_timeout,
        )
        if reset_code != 0:
            write_challenge_metadata(
                task_dir,
                experiment_name=args.experiment_name,
                run_id=resolved_run_id,
                challenge_name=task,
                time_start=task_started_wall,
                time_end=wall_clock_stamp(),
                exploit_status="failed",
            )
            print(f"[FAIL] {task}: reset exited {reset_code}")
            exit_code = 1
            if not args.continue_on_failure:
                break
            continue

        target_url = extract_target_url_from_output(reset_output)
        if not target_url:
            write_challenge_metadata(
                task_dir,
                experiment_name=args.experiment_name,
                run_id=resolved_run_id,
                challenge_name=task,
                time_start=task_started_wall,
                time_end=wall_clock_stamp(),
                exploit_status="failed",
            )
            print(f"[FAIL] {task}: missing target URL")
            exit_code = 1
            if not args.continue_on_failure:
                break
            continue

        print(f"[TARGET_URL] {target_url}")
        pentest_command = [
            *python_command,
            str(cli_script),
            "vulnbot",
            "-m",
            str(args.max_interactions),
            "--no-preload",
            "--no-save",
            "--task-prompt",
            task_prompt,
        ]
        if args.verify_prompt_flow:
            pentest_command.append("--print-init-description")

        pentest_env = os.environ.copy()
        pentest_env["PENTEST_LOG_FILE"] = str(autopentest_log)
        pentest_env["PENTEST_DISABLE_FILE_LOG"] = "1"
        pentest_env["PENTEST_TARGET_URL"] = target_url
        pentest_env["VULNBOT_SHELL_MODE"] = "local"

        pentest_code, pentest_seconds, _ = run_logged(
            pentest_command,
            vulnbot_root,
            autopentest_log,
            timeout=args.pentest_timeout,
            env=pentest_env,
        )

        exploit_status = "success" if args.verify_prompt_flow and pentest_code == 0 else "failed"
        exploit_error = "" if args.verify_prompt_flow and pentest_code == 0 else ""
        if not args.verify_prompt_flow:
            exploit_status, exploit_error = evaluate_exploit_status(task, pentest_code, autopentest_log)

        write_challenge_metadata(
            task_dir,
            experiment_name=args.experiment_name,
            run_id=resolved_run_id,
            challenge_name=task,
            time_start=task_started_wall,
            time_end=wall_clock_stamp(),
            exploit_status=exploit_status,
        )
        results.append(
            RunResult(
                task=task,
                status=exploit_status,
                target_url=target_url,
                reset_seconds=round(reset_seconds, 3),
                pentest_seconds=round(pentest_seconds, 3),
                reset_exit_code=reset_code,
                pentest_exit_code=pentest_code,
                error=exploit_error,
                autopentest_log=str(autopentest_log),
            )
        )

        if exploit_status == "success":
            print(f"[OK] {task}")
        else:
            print(f"[FAIL] {task}: {exploit_error or f'pentest exited {pentest_code}'}")
            exit_code = 1
            if not args.continue_on_failure:
                break

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
