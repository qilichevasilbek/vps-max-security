#!/bin/bash
# module_loader.sh — Module discovery, check-then-apply loop

readonly VMS_MODULES_DIR="${VMS_DIR}/modules"

# Discover all modules sorted by numeric prefix
module_list_all() {
    # Glob already returns sorted on most systems, but sort explicitly
    for f in "${VMS_MODULES_DIR}"/*.sh; do
        [[ -f "${f}" ]] || continue
        echo "${f}"
    done | sort
}

# Extract module name from filename: 03-ssh-hardening.sh → ssh-hardening
module_name_from_file() {
    local file="$1"
    local base
    base="$(basename "${file}" .sh)"
    # Strip numeric prefix: 03-ssh-hardening → ssh-hardening
    echo "${base#[0-9][0-9]-}"
}

# Extract module number from filename
module_num_from_file() {
    local file="$1"
    local base
    base="$(basename "${file}" .sh)"
    echo "${base%%-*}"
}

# Convert module name to function-safe name: ssh-hardening → ssh_hardening
module_func_name() {
    local name="$1"
    echo "${name//-/_}"
}

# Check if module should run based on --only/--skip filters
module_should_run() {
    local name="$1"

    # If --only is set, module must be in the list
    if [[ -n "${ONLY_MODULES:-}" ]]; then
        [[ ",${ONLY_MODULES}," == *",${name},"* ]] && return 0
        return 1
    fi

    # If --skip is set, module must NOT be in the list
    if [[ -n "${SKIP_MODULES:-}" ]]; then
        [[ ",${SKIP_MODULES}," == *",${name},"* ]] && return 1
    fi

    return 0
}

# Run a single module: check → apply
module_run() {
    local file="$1"
    local name
    name="$(module_name_from_file "${file}")"
    local num
    num="$(module_num_from_file "${file}")"
    local func
    func="$(module_func_name "${name}")"

    # Source the module
    # shellcheck disable=SC1090
    source "${file}"

    local desc="${name//-/ }"

    # Check if module should run based on filters
    if ! module_should_run "${name}"; then
        return 0
    fi

    ui_module_start "${num}" "${name}" "${desc}"

    # Dry-run mode
    if [[ "${DRY_RUN}" == "true" ]]; then
        if type "check_${func}" &>/dev/null; then
            if "check_${func}" 2>/dev/null; then
                ui_module_result "skipped" "${name}"
                state_set "${name}" "skipped"
            else
                ui_module_result "dry-run" "${name}"
            fi
        else
            ui_module_result "dry-run" "${name}"
        fi
        return 0
    fi

    # Check if already applied (idempotency)
    if type "check_${func}" &>/dev/null; then
        if "check_${func}" 2>/dev/null; then
            ui_module_result "skipped" "${name}"
            state_set "${name}" "skipped"
            return 0
        fi
    fi

    # Apply the module
    if type "apply_${func}" &>/dev/null; then
        if "apply_${func}"; then
            ui_module_result "applied" "${name}"
            state_set "${name}" "applied"
        else
            ui_module_result "failed" "${name}"
            state_set "${name}" "failed"
            log_error "Module ${name} failed!"
            return 1
        fi
    else
        log_error "Module ${name} has no apply function!"
        return 1
    fi
}

# Run all modules in sequence
module_run_all() {
    local applied=0 skipped=0 failed=0
    local total
    total="$(module_list_all | wc -l | tr -d ' ')"

    log_info "Running ${total} hardening modules..."

    while IFS= read -r file; do
        [[ -z "${file}" ]] && continue
        if module_run "${file}"; then
            local name
            name="$(module_name_from_file "${file}")"
            local mstate
            mstate="$(state_get "${name}")"
            case "${mstate}" in
                *applied*) ((applied++)) ;;
                *skipped*) ((skipped++)) ;;
            esac
        else
            ((failed++)) || true
        fi
    done < <(module_list_all)

    echo ""
    log_info "Results: ${applied} applied, ${skipped} skipped, ${failed} failed"
}

# Run audit on all modules
module_audit_all() {
    while IFS= read -r file; do
        [[ -z "${file}" ]] && continue
        local name
        name="$(module_name_from_file "${file}")"
        local func
        func="$(module_func_name "${name}")"

        # Source the module
        # shellcheck disable=SC1090
        source "${file}"

        if type "audit_${func}" &>/dev/null; then
            local score
            score="$("audit_${func}" 2>/dev/null)"
            echo "${name}|${score}"
        fi
    done < <(module_list_all)
}
