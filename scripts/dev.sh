#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-status}"
COMPONENT="${2:-telemetry-api}"

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PATH="$ROOT_PATH/.venv"
PYTHON_PATH="$VENV_PATH/bin/python"
RUN_PATH="$ROOT_PATH/.run"
LOG_PATH="$ROOT_PATH/.logs"
HOST_ADDRESS="${HOST_ADDRESS:-0.0.0.0}"
COLLECTOR_URL="${COLLECTOR_URL:-http://127.0.0.1:8011/telemetry}"

declare -A SERVICE_PORTS=(
  ["telemetry-api"]="8011"
  ["policy-service"]="8002"
  ["evaluation-engine"]="8003"
  ["enforcement-service"]="8004"
)

declare -A SERVICE_DIRS=(
  ["telemetry-api"]="$ROOT_PATH/services/telemetry-api"
  ["policy-service"]="$ROOT_PATH/services/policy-service"
  ["evaluation-engine"]="$ROOT_PATH/services/evaluation-engine"
  ["enforcement-service"]="$ROOT_PATH/services/enforcement-service"
)

declare -A SERVICE_APPS=(
  ["telemetry-api"]="app.main:app"
  ["policy-service"]="app.main:app"
  ["evaluation-engine"]="app.main:app"
  ["enforcement-service"]="app.main:app"
)

ensure_directory() {
  mkdir -p "$1"
}

ensure_venv() {
  if [[ ! -x "$PYTHON_PATH" ]]; then
    echo "Creating virtual environment at $VENV_PATH"
    python3 -m venv "$VENV_PATH"
  fi
}

install_repo() {
  ensure_venv
  echo "Installing shared package and service dependencies..."
  "$PYTHON_PATH" -m pip install --upgrade pip
  "$PYTHON_PATH" -m pip install -e "$ROOT_PATH/shared"

  for service in telemetry-api policy-service evaluation-engine enforcement-service; do
    (
      cd "${SERVICE_DIRS[$service]}"
      "$PYTHON_PATH" -m pip install -r requirements.txt
    )
  done
}

service_env_exports() {
  local name="$1"
  case "$name" in
    evaluation-engine)
      cat <<EOF
export TELEMETRY_API_URL="${TELEMETRY_API_URL:-http://127.0.0.1:8011}"
export POLICY_SERVICE_URL="${POLICY_SERVICE_URL:-http://127.0.0.1:8002}"
export ENFORCEMENT_SERVICE_URL="${ENFORCEMENT_SERVICE_URL:-http://127.0.0.1:8004}"
EOF
      ;;
    enforcement-service)
      cat <<EOF
export FORTIGATE_BASE_URL="${FORTIGATE_BASE_URL:-http://127.0.0.1:65535}"
export FORTIGATE_TOKEN="${FORTIGATE_TOKEN:-dev-token}"
export HTTP_TIMEOUT_SECONDS="${HTTP_TIMEOUT_SECONDS:-2}"
export HTTP_RETRIES="${HTTP_RETRIES:-1}"
EOF
      ;;
  esac
}

get_service_pid() {
  local name="$1"
  local port="${SERVICE_PORTS[$name]}"
  pgrep -f "$PYTHON_PATH -m uvicorn .* --port $port" | head -n 1 || true
}

start_service_background() {
  local name="$1"
  local port="${SERVICE_PORTS[$name]}"
  local pid_file="$RUN_PATH/$name.pid"
  local stdout="$LOG_PATH/$name.out.log"
  local stderr="$LOG_PATH/$name.err.log"
  local work_dir="${SERVICE_DIRS[$name]}"
  local app="${SERVICE_APPS[$name]}"
  local existing_pid

  ensure_directory "$RUN_PATH"
  ensure_directory "$LOG_PATH"

  existing_pid="$(get_service_pid "$name")"
  if [[ -n "$existing_pid" ]]; then
    echo "$existing_pid" > "$pid_file"
    echo "$name is already running with PID $existing_pid"
    return
  fi

  (
    cd "$work_dir"
    eval "$(service_env_exports "$name")"
    nohup "$PYTHON_PATH" -m uvicorn "$app" --host "$HOST_ADDRESS" --port "$port" >>"$stdout" 2>>"$stderr" &
    echo $! > "$pid_file"
  )

  sleep 1
  existing_pid="$(get_service_pid "$name")"
  if [[ -n "$existing_pid" ]]; then
    echo "$existing_pid" > "$pid_file"
    echo "Started $name on port $port with PID $existing_pid"
  else
    echo "Started $name, but the service PID could not be resolved"
  fi
}

stop_service_background() {
  local name="$1"
  local pid_file="$RUN_PATH/$name.pid"
  local pid=""

  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
  fi

  if [[ -z "$pid" ]]; then
    pid="$(get_service_pid "$name")"
  fi

  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid"
    fi
    echo "Stopped $name (PID $pid)"
  else
    echo "$name is not running"
  fi

  rm -f "$pid_file"
}

stop_orphan_repo_processes() {
  for service in "${!SERVICE_PORTS[@]}"; do
    local pid
    pid="$(get_service_pid "$service")"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" || true
      sleep 1
      if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" || true
      fi
      echo "Stopped orphan repo service process for $service (PID $pid)"
    fi
  done
}

show_status() {
  for service in enforcement-service telemetry-api evaluation-engine policy-service; do
    local pid
    pid="$(get_service_pid "$service")"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      printf "%-20s running (PID %s)\n" "$service" "$pid"
    else
      printf "%-20s stopped\n" "$service"
    fi
  done
}

run_service_foreground() {
  local name="$1"
  local port="${SERVICE_PORTS[$name]}"
  local work_dir="${SERVICE_DIRS[$name]}"
  local app="${SERVICE_APPS[$name]}"

  cd "$work_dir"
  eval "$(service_env_exports "$name")"
  exec "$PYTHON_PATH" -m uvicorn "$app" --host "$HOST_ADDRESS" --port "$port"
}

run_python_collector() {
  local collector_path="$ROOT_PATH/endpoint-collector/python_collector/collector.py"
  exec "$PYTHON_PATH" "$collector_path" --url "$COLLECTOR_URL"
}

run_python_collector_service() {
  local collector_path="$ROOT_PATH/endpoint-collector/python_collector/collector.py"
  local config_path="$ROOT_PATH/endpoint-collector/python_collector/example-config.toml"
  exec "$PYTHON_PATH" "$collector_path" run --config "$config_path"
}

run_frontend() {
  cd "$ROOT_PATH/frontend"
  exec npm run dev
}

usage() {
  cat <<'EOF'
Usage:
  ./scripts/dev.sh setup
  ./scripts/dev.sh run telemetry-api
  ./scripts/dev.sh run policy-service
  ./scripts/dev.sh run evaluation-engine
  ./scripts/dev.sh run enforcement-service
  ./scripts/dev.sh run python-collector
  ./scripts/dev.sh run python-collector-service
  ./scripts/dev.sh run frontend
  ./scripts/dev.sh start-all
  ./scripts/dev.sh status
  ./scripts/dev.sh stop
EOF
}

case "$ACTION" in
  setup)
    install_repo
    echo "Setup complete."
    ;;
  run)
    ensure_venv
    case "$COMPONENT" in
      telemetry-api|policy-service|evaluation-engine|enforcement-service)
        run_service_foreground "$COMPONENT"
        ;;
      python-collector)
        run_python_collector
        ;;
      python-collector-service)
        run_python_collector_service
        ;;
      frontend)
        run_frontend
        ;;
      *)
        usage
        exit 1
        ;;
    esac
    ;;
  start-all)
    ensure_venv
    for service in telemetry-api policy-service enforcement-service evaluation-engine; do
      start_service_background "$service"
    done
    echo "All services started. Logs are under $LOG_PATH"
    ;;
  stop)
    for service in telemetry-api policy-service evaluation-engine enforcement-service; do
      stop_service_background "$service"
    done
    stop_orphan_repo_processes
    ;;
  status)
    show_status
    ;;
  *)
    usage
    exit 1
    ;;
esac
