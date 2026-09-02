#!/usr/bin/env bash

set -euo pipefail

BENCHMARK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BENCHMARK_ROOT"

usage() {
    cat <<'EOF'
Usage: reset_docker_up.sh TASK_ID [docker compose up options]

Reset Docker state and start a specific benchmark task.

Supported task IDs:
  - CVE-* under annotations/Benchmark/vulhub
  - XBEN-* under annotations/Benchmark/xbow/benchmarks

Default behavior matches the CVE2PoC benchmark reset script:
  - remove all Docker containers
  - prune unused Docker networks
  - remove all non-Kali Docker images except ubuntu:22.04
  - run docker compose down -v --remove-orphans for the selected task
  - run docker compose up -d for Vulhub tasks
  - run docker compose build with deterministic FLAG and up -d --wait for XBEN tasks
  - detect the published target URL and print it to stdout

Options:
  --dry-run          Print actions without executing Docker commands.
  --no-image-prune  Do not remove Docker images.
  --stop-only        Only stop the selected task and remove its volumes/orphans.
  -h, --help        Show this help.

Examples:
  annotations/Benchmark/scripts/reset_docker_up.sh CVE-2022-22963
  annotations/Benchmark/scripts/reset_docker_up.sh 2022-22963 --no-image-prune
  annotations/Benchmark/scripts/reset_docker_up.sh XBEN-001-24
EOF
}

dry_run=0
image_prune=1
stop_only=0
task=""
compose_args=()
cookie_jar="/tmp/pentest_cookies.txt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --dry-run)
            dry_run=1
            shift
            ;;
        --no-image-prune)
            image_prune=0
            shift
            ;;
        --stop-only)
            stop_only=1
            shift
            ;;
        *)
            if [[ -z "$task" ]]; then
                task="$1"
            else
                compose_args+=("$1")
            fi
            shift
            ;;
    esac
done

if [[ -z "$task" ]]; then
    usage
    exit 1
fi

if [[ "$task" =~ ^XBEN- ]]; then
    task_kind="xben"
elif [[ "$task" =~ ^CVE- ]]; then
    task_kind="vulhub"
else
    task="CVE-${task}"
    task_kind="vulhub"
fi

if [[ "$task_kind" == "xben" ]]; then
    challenge_dir="xbow/benchmarks/${task}"
else
    challenge_dir="vulhub/${task}"
fi

if [[ ! -d "$challenge_dir" ]]; then
    echo "Unknown benchmark task: ${task}" >&2
    if [[ "$task_kind" == "xben" ]]; then
        echo "Available XBEN tasks:" >&2
        find xbow/benchmarks -maxdepth 1 -type d -name 'XBEN-*' -printf '  - %f\n' | sort >&2
    else
        echo "Available CVEs:" >&2
        find vulhub -maxdepth 1 -type d -name 'CVE-*' -printf '  - %f\n' | sort >&2
    fi
    exit 1
fi

compose_file=""
if [[ -f "${challenge_dir}/docker-compose.yml" ]]; then
    compose_file="docker-compose.yml"
elif [[ -f "${challenge_dir}/compose.yml" ]]; then
    compose_file="compose.yml"
else
    echo "No compose file found for Vulhub task: ${task}" >&2
    exit 1
fi

if docker compose version >/dev/null 2>&1; then
    compose=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    compose=(docker-compose)
else
    echo "Docker Compose is not available." >&2
    exit 1
fi

run() {
    echo "+ $*"
    if [[ "$dry_run" -eq 0 ]]; then
        "$@"
    fi
}

compose_up_with_network_retry() {
    local output_file="$1"
    shift

    if [[ "$dry_run" -eq 1 ]]; then
        echo "+ $*"
        return 0
    fi

    set +e
    "$@" >"$output_file" 2>&1
    local rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        cat "$output_file"
        return 0
    fi

    if grep -qiE "all predefined address pools have been fully subnetted|failed to create network" "$output_file"; then
        cat "$output_file"
        echo "[NETWORK_RECOVERY] Docker network pool exhausted. Pruning unused networks and retrying once..."
        docker network prune -f
        set +e
        "$@" >"$output_file" 2>&1
        rc=$?
        set -e
        if [[ $rc -ne 0 ]] && grep -qiE "all predefined address pools have been fully subnetted|failed to create network" "$output_file"; then
            cat <<'EOF'
[NETWORK_RECOVERY] Retry failed. Docker daemon address pools are exhausted.
[NETWORK_RECOVERY] Required action: expand Docker default-address-pools and restart Docker.
[NETWORK_RECOVERY] Docker Desktop:
  Settings -> Docker Engine, then add for example:
  {
    "default-address-pools": [
      { "base": "172.30.0.0/16", "size": 24 },
      { "base": "172.31.0.0/16", "size": 24 },
      { "base": "192.168.0.0/16", "size": 24 }
    ]
  }
[NETWORK_RECOVERY] Linux daemon:
  edit /etc/docker/daemon.json with the same default-address-pools block
  then run: sudo systemctl restart docker
EOF
        fi
    fi

    cat "$output_file"
    return $rc
}

compose_up_with_explicit_subnet_retry() {
    local output_file="$1"
    shift

    local task_seed
    task_seed=$(printf '%s' "${task}" | cksum | awk '{print $1}')
    local attempt subnet_octet subnet override_file rc
    local up_args=(-d)
    if [[ "$task_kind" == "xben" ]]; then
        up_args+=("--wait")
    fi

    for attempt in $(seq 0 15); do
        subnet_octet=$(( (task_seed + attempt) % 200 + 20 ))
        subnet="172.30.${subnet_octet}.0/24"
        override_file="/tmp/${task}.network-override.yml"
        cat >"$override_file" <<EOF
networks:
  default:
    ipam:
      config:
        - subnet: ${subnet}
EOF
        echo "[NETWORK_RECOVERY] Retrying with explicit subnet ${subnet}"
        set +e
        "${compose[@]}" -f "$compose_file" -f "$override_file" up "${up_args[@]}" "${compose_args[@]}" >"$output_file" 2>&1
        rc=$?
        set -e
        cat "$output_file"
        if [[ $rc -eq 0 ]]; then
            return 0
        fi
        if ! grep -qiE "all predefined address pools have been fully subnetted|failed to create network|Pool overlaps" "$output_file"; then
            return $rc
        fi
    done

    return 1
}

reset_cookie_jar() {
    echo "+ rm -f ${cookie_jar}"
    if [[ "$dry_run" -eq 0 ]]; then
        rm -f "${cookie_jar}"
    fi
}

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read())[1:-1])'
}

detect_target_url() {
    local project_dir="$1"
    local detected=""
    local fallback=""

    while read -r container_id; do
        [[ -z "$container_id" ]] && continue
        while read -r mapping; do
            [[ -z "$mapping" ]] && continue
            local container_port host_port host protocol url
            container_port=$(echo "$mapping" | awk '{print $1}' | cut -d/ -f1)
            host_port=$(echo "$mapping" | sed -nE 's/.*:([0-9]+)$/\1/p')
            [[ -z "$host_port" ]] && continue

            protocol="http"
            if [[ "$container_port" == "443" || "$host_port" == "443" || "$task" == "CVE-2019-15107" ]]; then
                protocol="https"
            fi

            host="${TARGET_HOST:-127.0.0.1}"
            url="${protocol}://${host}:${host_port}"

            if [[ -z "$fallback" ]]; then
                fallback="$url"
            fi

            case "$container_port" in
                80|8080|8081|8090|10000|7860)
                    detected="$url"
                    break
                    ;;
            esac
        done < <(docker port "$container_id" 2>/dev/null || true)

        [[ -n "$detected" ]] && break
    done < <("${compose[@]}" -f "$compose_file" ps -q)

    if [[ -z "$detected" ]]; then
        detected="$fallback"
    fi

    if [[ -n "$detected" ]]; then
        echo ""
        echo "TARGET_URL=${detected}"
    else
        echo "WARNING: Could not detect a published target URL from Docker port mappings." >&2
    fi
}

echo "Selected task: ${task}"
echo "Task kind: ${task_kind}"
echo "Challenge dir: ${BENCHMARK_ROOT}/${challenge_dir}"
echo "Compose file: ${compose_file}"
echo ""

reset_cookie_jar

if [[ "$stop_only" -eq 1 ]]; then
    echo "Stopping ${task}..."
    (
        cd "$challenge_dir"
        run "${compose[@]}" -f "$compose_file" down -v --remove-orphans
    )
    exit 0
fi

echo "Removing all Docker containers..."
if [[ "$dry_run" -eq 1 ]]; then
    echo "+ docker ps -aq | xargs -r docker rm -f"
else
    # Keep Red-MIRROR's shared database alive across challenge resets.
    containers=$(docker ps -aq | while read -r container_id; do
        container_name=$(docker inspect -f '{{.Name}}' "$container_id" 2>/dev/null || true)
        if [[ "$container_name" != "/redmirror-mysql" ]]; then
            echo "$container_id"
        fi
    done)
    if [[ -n "$containers" ]]; then
        docker rm -f $containers
    else
        echo "No containers to remove."
    fi
fi

echo "Pruning unused Docker networks..."
run docker network prune -f

if [[ "$image_prune" -eq 1 ]]; then
    echo "Removing all non-Kali Docker images except ubuntu:22.04..."
    if [[ "$dry_run" -eq 1 ]]; then
        echo "+ docker image ls --format '{{.ID}} {{.Repository}}:{{.Tag}}' | filter non-Kali/non-ubuntu | docker rmi -f"
    else
        declare -A refs_by_id=()
        while read -r image_id image_ref; do
            [[ -z "${image_id:-}" || -z "${image_ref:-}" ]] && continue
            refs_by_id["$image_id"]+="${image_ref} "
        done < <(docker image ls --format '{{.ID}} {{.Repository}}:{{.Tag}}')

        remove_ids=()
        for image_id in "${!refs_by_id[@]}"; do
            refs="${refs_by_id[$image_id]}"
            if [[ ! "$refs" =~ (^|[[:space:]])cvebench/kali-[^[:space:]]+ ]] \
                && [[ ! "$refs" =~ (^|[[:space:]])kalilinux/kali-[^[:space:]]+ ]] \
                && [[ ! "$refs" =~ (^|[[:space:]])ubuntu:22\.04($|[[:space:]]) ]]; then
                remove_ids+=("$image_id")
            fi
        done

        if [[ ${#remove_ids[@]} -gt 0 ]]; then
            printf '%s\n' "${remove_ids[@]}" | sort -u | xargs -r docker rmi -f
        else
            echo "No removable non-Kali images found."
        fi
    fi
else
    echo "Skipping Docker image prune."
fi

echo "Starting ${task}..."
(
    cd "$challenge_dir"
    run "${compose[@]}" -f "$compose_file" down -v --remove-orphans
    compose_retry_log="/tmp/${task}.compose_up.log"
    if [[ "$task_kind" == "xben" ]]; then
        task_upper=$(echo "$task" | tr '[:lower:]' '[:upper:]')
        flag_hash=$(echo -n "$task_upper" | openssl sha256 -r | cut -d' ' -f1)
        flag_value="FLAG{${flag_hash}}"
        echo "XBEN flag: ${flag_value}"
        run "${compose[@]}" -f "$compose_file" build --build-arg "FLAG=${flag_value}" --build-arg "flag=${flag_value}"
        echo "+ ${compose[*]} -f ${compose_file} up -d --wait ${compose_args[*]}"
        if ! compose_up_with_network_retry "$compose_retry_log" "${compose[@]}" -f "$compose_file" up -d --wait "${compose_args[@]}"; then
            if grep -qiE "all predefined address pools have been fully subnetted|failed to create network" "$compose_retry_log"; then
                compose_up_with_explicit_subnet_retry "$compose_retry_log"
            else
                exit 1
            fi
        fi
    else
        echo "+ ${compose[*]} -f ${compose_file} up -d ${compose_args[*]}"
        if ! compose_up_with_network_retry "$compose_retry_log" "${compose[@]}" -f "$compose_file" up -d "${compose_args[@]}"; then
            if grep -qiE "all predefined address pools have been fully subnetted|failed to create network" "$compose_retry_log"; then
                compose_up_with_explicit_subnet_retry "$compose_retry_log"
            else
                exit 1
            fi
        fi
    fi
    if [[ "$dry_run" -eq 0 ]]; then
        "${compose[@]}" -f "$compose_file" ps
        detect_target_url "${BENCHMARK_ROOT}/${challenge_dir}"
    fi
)
