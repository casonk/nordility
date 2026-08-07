#!/usr/bin/env bash
# Shared, source-only helpers for staging Nordility's root service runtime.

NORDILITY_RUNTIME_ROOT="/opt/nordility"
NORDILITY_RUNTIME_SOURCE_ROOT="${NORDILITY_RUNTIME_ROOT}/src"
NORDILITY_RUNTIME_PACKAGE_ROOT="${NORDILITY_RUNTIME_SOURCE_ROOT}/nordility"
NORDILITY_RUNTIME_FILES=(
  "__init__.py"
  "__main__.py"
  "cli.py"
  "client.py"
  "token_login.py"
  "web.py"
)

readonly NORDILITY_RUNTIME_ROOT
readonly NORDILITY_RUNTIME_SOURCE_ROOT
readonly NORDILITY_RUNTIME_PACKAGE_ROOT
readonly -a NORDILITY_RUNTIME_FILES

nordility_runtime_error() {
  printf 'error: %s\n' "$*" >&2
  return 1
}

nordility_require_single_line() {
  local label="$1"
  local value="$2"

  if [[ "${value}" == *$'\n'* || "${value}" == *$'\r'* ]]; then
    nordility_runtime_error "${label} must be a single line"
  fi
}

nordility_locate_python() {
  local requested="$1"
  local candidate

  nordility_require_single_line "Python executable" "${requested}" || return 1
  [[ -n "${requested}" ]] || {
    nordility_runtime_error "Python executable cannot be empty"
    return 1
  }

  if [[ "${requested}" == */* ]]; then
    candidate="${requested}"
  else
    candidate="$(command -v -- "${requested}" 2>/dev/null)" || {
      nordility_runtime_error "Python executable not found: ${requested}"
      return 1
    }
  fi

  [[ "${candidate}" == /* ]] || {
    nordility_runtime_error "Python executable must resolve to an absolute path: ${requested}"
    return 1
  }
  printf '%s\n' "${candidate}"
}

nordility_python_for_render() {
  local candidate
  local physical_dir

  candidate="$(nordility_locate_python "$1")" || return 1
  physical_dir="$(cd -P -- "$(dirname -- "${candidate}")" 2>/dev/null && pwd)" || {
    nordility_runtime_error "Python executable directory does not exist: ${candidate}"
    return 1
  }
  printf '%s/%s\n' "${physical_dir}" "$(basename -- "${candidate}")"
}

nordility_require_install_tools() {
  local command_name

  for command_name in cmp find install mktemp mv readlink rm sort stat; do
    command -v "${command_name}" >/dev/null 2>&1 || {
      nordility_runtime_error "required install command not found: ${command_name}"
      return 1
    }
  done
}

nordility_mode_is_not_group_or_world_writable() {
  local path="$1"
  local mode
  local mode_value

  mode="$(stat -c '%a' -- "${path}")" || return 1
  [[ "${mode}" =~ ^[0-7]+$ ]] || {
    nordility_runtime_error "could not read an octal mode for ${path}"
    return 1
  }
  mode_value=$((8#${mode}))
  (( (mode_value & 0022) == 0 ))
}

nordility_validate_directory() {
  local path="$1"
  local expected_uid="$2"
  local expected_gid="$3"
  local label="$4"
  local actual_uid
  local actual_gid

  [[ ! -L "${path}" ]] || {
    nordility_runtime_error "${label} must not be a symlink: ${path}"
    return 1
  }
  [[ -d "${path}" ]] || {
    nordility_runtime_error "${label} must be a directory: ${path}"
    return 1
  }
  actual_uid="$(stat -c '%u' -- "${path}")" || return 1
  actual_gid="$(stat -c '%g' -- "${path}")" || return 1
  [[ "${actual_uid}" == "${expected_uid}" ]] || {
    nordility_runtime_error "${label} has owner ${actual_uid}, expected ${expected_uid}: ${path}"
    return 1
  }
  if [[ "${expected_gid}" != "*" && "${actual_gid}" != "${expected_gid}" ]]; then
    nordility_runtime_error \
      "${label} has group ${actual_gid}, expected ${expected_gid}: ${path}"
    return 1
  fi
  nordility_mode_is_not_group_or_world_writable "${path}" || {
    nordility_runtime_error "${label} must not be group/world writable: ${path}"
    return 1
  }
}

nordility_validate_regular_file() {
  local path="$1"
  local expected_uid="$2"
  local expected_gid="$3"
  local label="$4"
  local actual_uid
  local actual_gid

  [[ ! -L "${path}" ]] || {
    nordility_runtime_error "${label} must not be a symlink: ${path}"
    return 1
  }
  [[ -f "${path}" ]] || {
    nordility_runtime_error "${label} must be a regular file: ${path}"
    return 1
  }
  actual_uid="$(stat -c '%u' -- "${path}")" || return 1
  actual_gid="$(stat -c '%g' -- "${path}")" || return 1
  [[ "${actual_uid}" == "${expected_uid}" ]] || {
    nordility_runtime_error "${label} has owner ${actual_uid}, expected ${expected_uid}: ${path}"
    return 1
  }
  if [[ "${expected_gid}" != "*" && "${actual_gid}" != "${expected_gid}" ]]; then
    nordility_runtime_error \
      "${label} has group ${actual_gid}, expected ${expected_gid}: ${path}"
    return 1
  fi
  nordility_mode_is_not_group_or_world_writable "${path}" || {
    nordility_runtime_error "${label} must not be group/world writable: ${path}"
    return 1
  }
}

nordility_validate_root_path_chain() {
  local path="$1"
  local current

  current="$(dirname -- "${path}")"
  while :; do
    nordility_validate_directory "${current}" 0 0 "Python path directory" || return 1
    [[ "${current}" == "/" ]] && break
    current="$(dirname -- "${current}")"
  done
}

nordility_secure_python() {
  local candidate
  local resolved
  local mode
  local mode_value

  candidate="$(nordility_locate_python "$1")" || return 1
  resolved="$(readlink -f -- "${candidate}" 2>/dev/null)" || {
    nordility_runtime_error "could not resolve Python executable: ${candidate}"
    return 1
  }
  [[ -n "${resolved}" && "${resolved}" == /* ]] || {
    nordility_runtime_error "Python executable did not resolve to an absolute path: ${candidate}"
    return 1
  }

  nordility_validate_root_path_chain "${resolved}" || return 1
  nordility_validate_regular_file "${resolved}" 0 0 "Python executable" || return 1
  [[ -x "${resolved}" ]] || {
    nordility_runtime_error "Python executable is not executable: ${resolved}"
    return 1
  }
  mode="$(stat -c '%a' -- "${resolved}")" || return 1
  mode_value=$((8#${mode}))
  (( (mode_value & 06000) == 0 )) || {
    nordility_runtime_error "Python executable must not have setuid/setgid bits: ${resolved}"
    return 1
  }
  printf '%s\n' "${resolved}"
}

nordility_reject_unexpected_entries() {
  local directory="$1"
  shift
  local entry
  local entry_name
  local allowed_name
  local allowed

  while IFS= read -r -d '' entry; do
    entry_name="${entry##*/}"
    allowed=0
    for allowed_name in "$@"; do
      if [[ "${entry_name}" == "${allowed_name}" ]]; then
        allowed=1
        break
      fi
    done
    (( allowed == 1 )) || {
      nordility_runtime_error "unexpected entry in protected runtime: ${entry}"
      return 1
    }
  done < <(find "${directory}" -mindepth 1 -maxdepth 1 -print0)
}

nordility_validate_source_tree() {
  local repo_root="$1"
  local source_dir="${repo_root}/src/nordility"
  local repo_uid
  local filename

  nordility_validate_directory "${repo_root}" "$(stat -c '%u' -- "${repo_root}")" '*' \
    "repository root" || return 1
  repo_uid="$(stat -c '%u' -- "${repo_root}")" || return 1
  nordility_validate_directory "${repo_root}/src" "${repo_uid}" '*' \
    "source root" || return 1
  nordility_validate_directory "${source_dir}" "${repo_uid}" '*' \
    "Nordility source package" || return 1

  for filename in "${NORDILITY_RUNTIME_FILES[@]}"; do
    nordility_validate_regular_file "${source_dir}/${filename}" "${repo_uid}" '*' \
      "Nordility source file" || return 1
  done
}

nordility_prepare_runtime_tree() {
  local runtime_path

  nordility_validate_directory "/" 0 0 "filesystem root" || return 1
  nordility_validate_directory "/opt" 0 0 "runtime parent" || return 1

  for runtime_path in \
    "${NORDILITY_RUNTIME_ROOT}" \
    "${NORDILITY_RUNTIME_SOURCE_ROOT}" \
    "${NORDILITY_RUNTIME_PACKAGE_ROOT}"; do
    if [[ -e "${runtime_path}" || -L "${runtime_path}" ]]; then
      nordility_validate_directory "${runtime_path}" 0 0 "protected runtime directory" || \
        return 1
    fi
  done

  install -d -o root -g root -m 0755 \
    "${NORDILITY_RUNTIME_ROOT}" "${NORDILITY_RUNTIME_SOURCE_ROOT}"
  nordility_validate_directory "${NORDILITY_RUNTIME_ROOT}" 0 0 \
    "protected runtime root" || return 1
  nordility_validate_directory "${NORDILITY_RUNTIME_SOURCE_ROOT}" 0 0 \
    "protected runtime source root" || return 1
  nordility_reject_unexpected_entries "${NORDILITY_RUNTIME_ROOT}" "src" || return 1
  if [[ -d "${NORDILITY_RUNTIME_PACKAGE_ROOT}" ]]; then
    nordility_reject_unexpected_entries "${NORDILITY_RUNTIME_SOURCE_ROOT}" "nordility" || \
      return 1
    nordility_reject_unexpected_entries \
      "${NORDILITY_RUNTIME_PACKAGE_ROOT}" "${NORDILITY_RUNTIME_FILES[@]}" || return 1
    for runtime_path in "${NORDILITY_RUNTIME_FILES[@]}"; do
      nordility_validate_regular_file \
        "${NORDILITY_RUNTIME_PACKAGE_ROOT}/${runtime_path}" 0 0 \
        "protected runtime file" || return 1
    done
  else
    nordility_reject_unexpected_entries "${NORDILITY_RUNTIME_SOURCE_ROOT}" || return 1
  fi
}

nordility_stage_runtime() {
  local repo_root="$1"
  local source_dir="${repo_root}/src/nordility"
  local stage_dir
  local previous_dir=""
  local filename

  nordility_require_install_tools || return 1
  nordility_validate_source_tree "${repo_root}" || return 1
  nordility_prepare_runtime_tree || return 1

  stage_dir="$(mktemp -d "${NORDILITY_RUNTIME_SOURCE_ROOT}/.nordility.stage.XXXXXX")" || {
    nordility_runtime_error "could not create protected runtime staging directory"
    return 1
  }
  chown root:root "${stage_dir}"
  chmod 0755 "${stage_dir}"

  for filename in "${NORDILITY_RUNTIME_FILES[@]}"; do
    if ! install -o root -g root -m 0644 \
      "${source_dir}/${filename}" "${stage_dir}/${filename}"; then
      rm -rf -- "${stage_dir}"
      nordility_runtime_error "could not stage Nordility runtime file: ${filename}"
      return 1
    fi
    if ! cmp -s -- "${source_dir}/${filename}" "${stage_dir}/${filename}"; then
      rm -rf -- "${stage_dir}"
      nordility_runtime_error "staged Nordility runtime file did not verify: ${filename}"
      return 1
    fi
    if ! nordility_validate_regular_file "${stage_dir}/${filename}" 0 0 \
      "staged runtime file"; then
      rm -rf -- "${stage_dir}"
      return 1
    fi
  done
  nordility_reject_unexpected_entries "${stage_dir}" "${NORDILITY_RUNTIME_FILES[@]}" || {
    rm -rf -- "${stage_dir}"
    return 1
  }

  if [[ -d "${NORDILITY_RUNTIME_PACKAGE_ROOT}" ]]; then
    previous_dir="${NORDILITY_RUNTIME_SOURCE_ROOT}/.nordility.previous.$$"
    [[ ! -e "${previous_dir}" && ! -L "${previous_dir}" ]] || {
      rm -rf -- "${stage_dir}"
      nordility_runtime_error "protected runtime backup path already exists: ${previous_dir}"
      return 1
    }
    if ! mv -- "${NORDILITY_RUNTIME_PACKAGE_ROOT}" "${previous_dir}"; then
      rm -rf -- "${stage_dir}"
      nordility_runtime_error "could not move the previous protected runtime aside"
      return 1
    fi
  fi

  if ! mv -- "${stage_dir}" "${NORDILITY_RUNTIME_PACKAGE_ROOT}"; then
    if [[ -n "${previous_dir}" ]]; then
      mv -- "${previous_dir}" "${NORDILITY_RUNTIME_PACKAGE_ROOT}" || true
    fi
    rm -rf -- "${stage_dir}"
    nordility_runtime_error "could not activate the staged protected runtime"
    return 1
  fi
  if [[ -n "${previous_dir}" ]]; then
    rm -rf -- "${previous_dir}"
  fi

  nordility_validate_directory "${NORDILITY_RUNTIME_PACKAGE_ROOT}" 0 0 \
    "protected runtime package" || return 1
  nordility_reject_unexpected_entries \
    "${NORDILITY_RUNTIME_PACKAGE_ROOT}" "${NORDILITY_RUNTIME_FILES[@]}" || return 1
  for filename in "${NORDILITY_RUNTIME_FILES[@]}"; do
    nordility_validate_regular_file \
      "${NORDILITY_RUNTIME_PACKAGE_ROOT}/${filename}" 0 0 \
      "protected runtime file" || return 1
  done
}
