#!/usr/bin/env bash

# Shared suite-case resolution for shell benchmark tooling.
# Resolution order: explicit env override -> manifest-derived count -> named fallback.

declare -Ar FALLBACK_SUITE_CASES=(
    [binpool]=236
    [cgc]=204
    [cyberseceval]=653
    [fixtures]=22
    [juliet]=54488
    [owasp]=2740
    [realworld]=6
)

suite_case_env_var_name() {
    local suite="$1"
    local normalized
    normalized="$(printf '%s' "$suite" | tr '[:lower:]-' '[:upper:]_')"
    printf 'SKWAQ_SUITE_CASES_%s' "$normalized"
}

validate_suite_case_count() {
    local value="$1"
    local source="$2"

    if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf 'ERROR: %s must be a positive integer, got %q\n' "$source" "$value" >&2
        return 1
    fi
}

count_cases_from_manifest() {
    local manifest_path="$1"

    if [[ ! -f "$manifest_path" ]]; then
        return 1
    fi

    grep -cE '^\[\[cases\]\]' "$manifest_path"
}

get_suite_cases() {
    local repo_root="$1"
    local suite="$2"
    local env_var_name env_value manifest_path manifest_value fallback_value

    env_var_name="$(suite_case_env_var_name "$suite")"
    env_value="${!env_var_name:-}"
    if [[ -n "$env_value" ]]; then
        validate_suite_case_count "$env_value" "$env_var_name" || return 1
        printf '%s' "$env_value"
        return 0
    fi

    manifest_path="$repo_root/data/gym/ground_truth/${suite}.toml"
    if manifest_value="$(count_cases_from_manifest "$manifest_path")"; then
        validate_suite_case_count "$manifest_value" "$manifest_path" || return 1
        printf '%s' "$manifest_value"
        return 0
    fi

    fallback_value="${FALLBACK_SUITE_CASES[$suite]:-}"
    if [[ -n "$fallback_value" ]]; then
        validate_suite_case_count "$fallback_value" "FALLBACK_SUITE_CASES[$suite]" || return 1
        printf 'WARNING: using fallback suite case count for %s: %s\n' "$suite" "$fallback_value" >&2
        printf '%s' "$fallback_value"
        return 0
    fi

    printf 'ERROR: unable to resolve suite case count for %s\n' "$suite" >&2
    return 1
}
