"""
test_secrets_agent.py
=====================
Validates the secrets_agent multi-stage filtering pipeline.
Tests the PIPELINE LOGIC directly - no gitleaks rules file required.

Run:  python test_secrets_agent.py
"""

import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from api.adk_agents.secrets_agent import (
    _run_pipeline,
    _extract_candidate,
    _is_context_fp,
    _is_rule_specific_fp,
    _fails_value_quality,
    _is_structural_fp,
    _shannon_entropy,
    _compute_confidence,
)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
INFO = "\033[94m ->\033[0m"

results = []


def check(name: str, condition: bool, detail: str = ""):
    symbol = PASS if condition else FAIL
    results.append(condition)
    print(f"  {symbol}  {name}")
    if detail:
        print(f"         {INFO} {detail}")


def check_detection(
    test_name: str,
    rule_id: str,
    line: str,
    candidate: str,
    rel_path: str = "api/config.py",
    expect_detect: bool = True,
    expect_comment: bool = False,
):
    is_fp, reason = _run_pipeline(rule_id, rel_path, line, candidate)
    in_comment = reason.startswith("in_comment_line:")

    if not is_fp:
        entropy = _shannon_entropy(candidate.strip("`'\" \t"))
        score, tier = _compute_confidence(rule_id, candidate, line, entropy)
        if in_comment:
            score = min(score, 50)
            tier = "MEDIUM" if score >= 40 else "LOW"
    else:
        score, tier = 0, "-"

    detected = not is_fp

    print(f"\n{'-' * 60}")
    print(f"  Test : {test_name}")
    print(f"  Line : {line.strip()[:80]}")
    print(f"  Cand : {candidate!r}")
    print(f"  Rule : {rule_id}")
    print(f"  {'Detected' if detected else 'Suppressed'} | reason={reason} | score={score} | tier={tier}")

    check(
        f"Detection correct (expect {'DETECT' if expect_detect else 'SUPPRESS'})",
        detected == expect_detect,
        f"is_fp={is_fp}, reason={reason}",
    )

    if expect_detect and expect_comment:
        check(
            "Marked as in_comment (downgraded, not suppressed)",
            in_comment,
            f"in_comment={in_comment}, reason={reason}",
        )

    return detected, in_comment, reason, score, tier


print("\n" + "=" * 60)
print("TEST 1 - Real live Stripe key")
candidate = "sk_live_abcdefghijklmnop"
line = 'api_key = "sk_live_abcdefghijklmnop"'

detected, in_comment, reason, score, tier = check_detection(
    "Real live Stripe key",
    "stripe-api-key",
    line,
    candidate,
    expect_detect=True,
    expect_comment=False,
)
check("Not marked as comment", not in_comment)
check("Confidence tier is HIGH or MEDIUM", tier in ("HIGH", "MEDIUM"), f"tier={tier}, score={score}")

print("\n" + "=" * 60)
print("TEST 2 - Test key hardcoded in production config")
candidate = "sk_test_abcdefghijklmnop"
line = 'api_key = "sk_test_abcdefghijklmnop"'

detected, _, reason, score, tier = check_detection(
    "Test Stripe key in prod code",
    "stripe-api-key",
    line,
    candidate,
    expect_detect=True,
)
check("Confidence tier is not LOW", tier != "LOW", f"tier={tier}, score={score}")
fp_reason = _is_rule_specific_fp("stripe-api-key", candidate, line)
check("Rule-specific filter does NOT suppress sk_test_ key", fp_reason is None, f"_is_rule_specific_fp returned: {fp_reason}")

print("\n" + "=" * 60)
print("TEST 3 - Fake placeholder value")
candidate = "test_value_123"
line = 'apiKey = "test_value_123"'

detected, _, reason, score, tier = check_detection(
    "Placeholder/fake variable",
    "generic-api-key",
    line,
    candidate,
    expect_detect=False,
)

struct_reason = _is_structural_fp(candidate)
quality_reason = _fails_value_quality("generic-api-key", candidate)
entropy_val = _shannon_entropy(candidate)
print(f"         {INFO} entropy={entropy_val:.2f}, struct_fp={struct_reason}, quality_fp={quality_reason}")
check(
    "Suppressed at structural or quality stage",
    struct_reason is not None or quality_reason is not None or not detected,
    f"struct={struct_reason}, quality={quality_reason}",
)

print("\n" + "=" * 60)
print("TEST 4 - Secret embedded in a comment")
candidate = "sk_live_abcdefghijklmnop"
line = '# secret_key = "sk_live_abcdefghijklmnop"'

detected, in_comment, reason, score, tier = check_detection(
    "Secret in comment (must detect at MEDIUM)",
    "stripe-api-key",
    line,
    candidate,
    expect_detect=True,
    expect_comment=True,
)
check("Confidence capped at MEDIUM/LOW (not HIGH)", tier in ("MEDIUM", "LOW"), f"tier={tier}, score={score}")
check("Score <= 50", score <= 50, f"score={score}")

print("\n" + "=" * 60)
print("TEST 5 - .env space-delimited format")
candidate = "sk_live_abcdefghijklmnop"
line = "STRIPE_SECRET_KEY sk_live_abcdefghijklmnop"
ctx_reason = _is_context_fp("stripe-api-key", line, candidate)
print(f"         {INFO} _is_context_fp returned: {ctx_reason!r}")
check(
    "_is_context_fp does NOT return 'no_assignment_operator' for .env format",
    ctx_reason != "stage6_context:no_assignment_operator" and (ctx_reason is None or ctx_reason.startswith("in_comment")),
    f"ctx_reason={ctx_reason}",
)

detected, _, reason, score, tier = check_detection(
    ".env space-delimited Stripe key",
    "stripe-api-key",
    line,
    candidate,
    expect_detect=True,
)

print("\n" + "=" * 60)
print("EXTRA 1 - File path gate: secrets in .env files themselves")
candidate = "sk_live_abcdefghijklmnop"
line = 'STRIPE_SECRET_KEY="sk_live_abcdefghijklmnop"'
detected, _, reason, score, tier = check_detection(
    ".env file with = operator",
    "stripe-api-key",
    line,
    candidate,
    rel_path=".env",
    expect_detect=True,
)

print("\n" + "=" * 60)
print("EXTRA 2 - Stripe webhook secret (whsec_)")
candidate = "whsec_abcdefghijklmnopqrstuvwxyz0123456789ABCD"
line = 'webhook_secret = "whsec_abcdefghijklmnopqrstuvwxyz0123456789ABCD"'
fp_reason = _is_rule_specific_fp("stripe-api-key", candidate, line)
check("whsec_ key NOT suppressed by rule-specific filter", fp_reason is None, f"_is_rule_specific_fp returned: {fp_reason}")

print("\n" + "=" * 60)
print("EXTRA 3 - Word boundary: 'schema' should not match 'schematica'")
line_with_schema = 'schematically_named_key = "sk_live_abcdefghijklmnop"'
ctx = _is_context_fp("stripe-api-key", line_with_schema, "sk_live_abcdefghijklmnop")
check("'schema' in 'schematically' does NOT trigger fp_context_token", ctx is None or not ctx.startswith("fp_context_token"), f"ctx_reason={ctx}")

print("\n" + "=" * 60)
print("EXTRA 5 - Short low-entropy candidate should be rejected by quality gate")
candidate = "abc12345"
quality = _fails_value_quality("generic-api-key", candidate)
check("Short low-entropy value rejected", quality is not None, f"_fails_value_quality returned: {quality}, entropy={_shannon_entropy(candidate):.2f}")

print("\n" + "=" * 60)
print("EXTRA 6 - _extract_candidate strips the LHS key name")
pattern = re.compile(r'(?:api_key|secret)\s*=\s*["\']?([a-zA-Z0-9_]{16,})')
line = 'api_key = "realSecretValue1234567890"'
match = pattern.search(line)
if match:
    extracted = _extract_candidate(match, line)
    check("Extracted candidate is the VALUE, not 'api_key = ...'", "api_key" not in extracted and "=" not in extracted, f"extracted={extracted!r}")
else:
    check("Pattern match found", False, "No match - test setup error")

print("\n" + "=" * 60)
total = len(results)
passed = sum(results)
failed = total - passed
print(f"\n  Results: {passed}/{total} passed")
if failed == 0:
    print("  ALL TESTS PASSED")
else:
    print(f"  {failed} FAILED")

sys.exit(0 if failed == 0 else 1)
