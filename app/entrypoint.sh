#!/bin/sh
set -eu

runtime_dir=/run/mihomo
core_dir=/data/mihomo
config_path="${runtime_dir}/config.yaml"
next_config_path="${runtime_dir}/config.next.yaml"
mapping_path=/data/ports.json
next_mapping_path="${runtime_dir}/ports.next.json"
core_pid=""
stopping=0

log() {
  printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

stop_core() {
  if [ -n "${core_pid}" ] && kill -0 "${core_pid}" 2>/dev/null; then
    kill -TERM "${core_pid}" 2>/dev/null || true
    wait "${core_pid}" 2>/dev/null || true
  fi
  core_pid=""
  rm -f "${runtime_dir}/mihomo.pid"
}

start_core() {
  /usr/local/bin/mihomo -d "${core_dir}" -f "${config_path}" &
  core_pid="$!"
  printf '%s\n' "${core_pid}" > "${runtime_dir}/mihomo.pid"
}

shutdown() {
  stopping=1
  stop_core
  exit 0
}

trap shutdown INT TERM

refresh() {
  rm -f "${next_config_path}" "${next_mapping_path}" "${next_mapping_path%.json}.csv"

  if ! python3 /app/generate_config.py \
    --output "${next_config_path}" \
    --mapping-output "${next_mapping_path}"; then
    log "Subscription refresh failed; keeping the previous configuration."
    return 1
  fi

  if ! /usr/local/bin/mihomo -d "${core_dir}" -f "${next_config_path}" -t; then
    log "Generated Mihomo configuration did not validate; keeping the previous configuration."
    return 1
  fi

  if [ -f "${config_path}" ] && cmp -s "${config_path}" "${next_config_path}"; then
    rm -f "${next_config_path}" "${next_mapping_path}" "${next_mapping_path%.json}.csv"
    if [ -z "${core_pid}" ] || ! kill -0 "${core_pid}" 2>/dev/null; then
      start_core
      log "Subscription unchanged; Mihomo restarted."
    else
      log "Subscription unchanged."
    fi
    return 0
  fi

  mv "${next_config_path}" "${config_path}"
  mv "${next_mapping_path}" "${mapping_path}"
  mv "${next_mapping_path%.json}.csv" "${mapping_path%.json}.csv"
  stop_core
  start_core
  log "Mihomo started with the refreshed subscription."
}

mkdir -p "${runtime_dir}" "${core_dir}"
update_interval="${UPDATE_INTERVAL_SECONDS:-3600}"
case "${update_interval}" in
  ''|*[!0-9]*) log "UPDATE_INTERVAL_SECONDS must be a positive integer."; exit 2 ;;
esac
if [ "${update_interval}" -lt 1 ]; then
  log "UPDATE_INTERVAL_SECONDS must be a positive integer."
  exit 2
fi

if ! refresh; then
  exit 1
fi

while [ "${stopping}" -eq 0 ]; do
  sleep "${update_interval}" &
  sleep_pid="$!"
  wait "${sleep_pid}" || true
  [ "${stopping}" -eq 1 ] && break

  if [ -n "${core_pid}" ] && ! kill -0 "${core_pid}" 2>/dev/null; then
    log "Mihomo exited unexpectedly; attempting a restart."
    core_pid=""
  fi
  refresh || true
done
