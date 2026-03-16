#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../scripts/lib/suite_cases.sh
source "$repo_root/scripts/lib/suite_cases.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

assert_eq() {
    local actual="$1"
    local expected="$2"
    local message="$3"
    if [[ "$actual" != "$expected" ]]; then
        fail "$message (expected=$expected actual=$actual)"
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        fail "$message (missing '$needle')"
    fi
}

assert_not_contains_file() {
    local path="$1"
    local needle="$2"
    local message="$3"
    if grep -qF "$needle" "$path"; then
        fail "$message ($path still contains '$needle')"
    fi
}

test_env_var_name() {
    assert_eq "$(suite_case_env_var_name juliet)" "SKWAQ_SUITE_CASES_JULIET" "juliet env var name"
    assert_eq "$(suite_case_env_var_name cybersec-eval)" "SKWAQ_SUITE_CASES_CYBERSEC_EVAL" "hyphen normalization"
}

test_manifest_count() {
    assert_eq "$(get_suite_cases "$repo_root" juliet)" "54488" "juliet manifest count"
    assert_eq "$(get_suite_cases "$repo_root" fixtures)" "22" "fixtures manifest count"
}

test_env_override_wins() {
    SKWAQ_SUITE_CASES_JULIET=123
    export SKWAQ_SUITE_CASES_JULIET
    assert_eq "$(get_suite_cases "$repo_root" juliet)" "123" "env override should win"
    unset SKWAQ_SUITE_CASES_JULIET
}

test_invalid_override_fails() {
    local output
    set +e
    output="$(SKWAQ_SUITE_CASES_JULIET=abc get_suite_cases "$repo_root" juliet 2>&1)"
    local status=$?
    set -e
    [[ $status -ne 0 ]] || fail "invalid override should fail"
    assert_contains "$output" "positive integer" "invalid override should explain failure"
}

test_missing_manifest_fails_loudly() {
    local temp_repo output
    temp_repo="$(mktemp -d)"
    mkdir -p "$temp_repo/data/gym/ground_truth"
    set +e
    output="$(get_suite_cases "$temp_repo" cgc 2>&1)"
    local status=$?
    set -e
    [[ $status -ne 0 ]] || fail "missing manifest should fail loudly"
    assert_contains "$output" "expected manifest at $temp_repo/data/gym/ground_truth/cgc.toml" "missing manifest path should be reported"
    assert_contains "$output" "SKWAQ_SUITE_CASES_CGC" "missing manifest should mention env override"
    rm -rf "$temp_repo"
}

test_empty_manifest_reports_invalid_count() {
    local temp_repo output manifest_path
    temp_repo="$(mktemp -d)"
    mkdir -p "$temp_repo/data/gym/ground_truth"
    manifest_path="$temp_repo/data/gym/ground_truth/fixtures.toml"
    cat >"$manifest_path" <<'EOF'
suite = "fixtures"
EOF
    set +e
    output="$(get_suite_cases "$temp_repo" fixtures 2>&1)"
    local status=$?
    set -e
    [[ $status -ne 0 ]] || fail "empty manifest should fail validation"
    assert_contains "$output" "$manifest_path" "empty manifest should identify manifest path"
    assert_contains "$output" "positive integer" "empty manifest should fail as invalid count"
    rm -rf "$temp_repo"
}

test_missing_suite_fails() {
    local temp_repo output
    temp_repo="$(mktemp -d)"
    mkdir -p "$temp_repo/data/gym/ground_truth"
    set +e
    output="$(get_suite_cases "$temp_repo" unknown_suite 2>&1)"
    local status=$?
    set -e
    [[ $status -ne 0 ]] || fail "unknown suite should fail"
    assert_contains "$output" "unable to resolve suite case count" "unknown suite error"
    rm -rf "$temp_repo"
}

test_scripts_source_shared_helper() {
    assert_contains "$(cat "$repo_root/scripts/gym-eval.sh")" 'source "$SCRIPT_DIR/lib/suite_cases.sh"' "gym-eval should source helper"
    assert_contains "$(cat "$repo_root/scripts/parallel-gym.sh")" 'source "$SCRIPT_DIR/lib/suite_cases.sh"' "parallel-gym should source helper"
}

test_eval_script_has_no_stale_suite_totals() {
    assert_not_contains_file "$repo_root/scripts/gym-eval.sh" "SUITE_CASES[juliet]=5000" "gym-eval should not hardcode juliet"
    assert_not_contains_file "$repo_root/scripts/gym-eval.sh" "SUITE_CASES[fixtures]=7" "gym-eval should not hardcode fixtures"
}

test_parallel_examples_drop_hardcoded_juliet_total() {
    assert_not_contains_file "$repo_root/scripts/parallel-gym.sh" "./scripts/parallel-gym.sh juliet 5000 10" "parallel-gym examples should not hardcode Juliet 5000"
}

test_manifest_counter_counts_cases() {
    local temp_repo manifest_path
    temp_repo="$(mktemp -d)"
    manifest_path="$temp_repo/sample.toml"
    cat >"$manifest_path" <<'EOF'
suite = "sample"

[[cases]]
id = "one"

[[cases]]
id = "two"
EOF
    assert_eq "$(count_cases_from_manifest "$manifest_path")" "2" "manifest counter"
    rm -rf "$temp_repo"
}

test_eval_script_seeds_fixtures_count_for_summary() {
    assert_contains "$(cat "$repo_root/scripts/gym-eval.sh")" \
        'SUITE_CASES["fixtures"]="$(get_suite_cases "$REPO_ROOT" fixtures)"' \
        "gym-eval should seed fixtures count before summary rendering"
}

test_total_cases_positional_override_still_validates() {
    validate_suite_case_count "50" "total_cases" >/dev/null
    set +e
    local output
    output="$(validate_suite_case_count "0" "total_cases" 2>&1)"
    local status=$?
    set -e
    [[ $status -ne 0 ]] || fail "zero total_cases should fail"
    assert_contains "$output" "positive integer" "explicit total validation"
}

main() {
    test_env_var_name
    test_manifest_count
    test_env_override_wins
    test_invalid_override_fails
    test_missing_manifest_fails_loudly
    test_empty_manifest_reports_invalid_count
    test_missing_suite_fails
    test_scripts_source_shared_helper
    test_eval_script_has_no_stale_suite_totals
    test_parallel_examples_drop_hardcoded_juliet_total
    test_manifest_counter_counts_cases
    test_eval_script_seeds_fixtures_count_for_summary
    test_total_cases_positional_override_still_validates
    echo "PASS: 13/13 tests"
}

main "$@"
