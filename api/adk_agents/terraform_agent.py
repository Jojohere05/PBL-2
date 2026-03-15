import os
import re

SKIP_DIRS = {".git"}


def _extract_blocks(content: str) -> list:
    results = []
    for m in re.finditer(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', content
    ):
        rtype, rname = m.group(1), m.group(2)
        start, depth, i = m.end(), 1, m.end()
        while i < len(content) and depth > 0:
            if content[i] == "{":   depth += 1
            elif content[i] == "}": depth -= 1
            i += 1
        results.append((rtype, rname, content[start:i - 1]))
    return results


def scan_terraform_files(repo_path: str) -> dict:
    """
    Scans .tf files for infrastructure misconfigurations.
    Returns raw violations — no LLM, no decisions.
    """
    violations = []
    tf_files   = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if fname.endswith(".tf"):
                tf_files.append(os.path.join(root, fname))

    for fpath in tf_files:
        rel = os.path.relpath(fpath, repo_path)
        try:
            content = open(fpath, "r", errors="ignore").read()
        except Exception:
            continue

        for rtype, rname, body in _extract_blocks(content):
            res = f"{rtype}.{rname}"

            checks = [
                (r'publicly_accessible\s*=\s*true',
                 "TF_DB_PUBLIC", "CRITICAL",
                 "Database is publicly accessible",
                 "infrastructure_risk"),
                (r'storage_encrypted\s*=\s*false',
                 "TF_STORAGE_UNENCRYPTED", "HIGH",
                 "Storage encryption disabled",
                 "infrastructure_risk"),
                (r'encrypt_at_rest\s*=\s*false',
                 "TF_ENCRYPT_AT_REST_DISABLED", "HIGH",
                 "Encrypt-at-rest disabled",
                 "infrastructure_risk"),
            ]
            for pattern, rule_id, sev, msg, dim in checks:
                if re.search(pattern, body):
                    violations.append({
                        "rule_id": rule_id, "file": rel,
                        "resource": res, "severity": sev,
                        "message": msg, "dimension": dim
                    })

            if "s3_bucket" in rtype:
                if re.search(r'acl\s*=\s*"public-read', body):
                    violations.append({
                        "rule_id": "TF_S3_PUBLIC_ACL", "file": rel,
                        "resource": res, "severity": "CRITICAL",
                        "message": "S3 bucket public-read ACL",
                        "dimension": "infrastructure_risk"
                    })
                if re.search(r'block_public_acls\s*=\s*false', body):
                    violations.append({
                        "rule_id": "TF_S3_PUBLIC_BLOCK_DISABLED",
                        "file": rel, "resource": res,
                        "severity": "HIGH",
                        "message": "S3 public access block disabled",
                        "dimension": "infrastructure_risk"
                    })

            if "security_group" in rtype:
                if re.search(
                    r'cidr_blocks\s*=\s*\[.*"0\.0\.0\.0/0"', body
                ):
                    violations.append({
                        "rule_id": "TF_SG_OPEN_INGRESS", "file": rel,
                        "resource": res, "severity": "HIGH",
                        "message": "Security group allows 0.0.0.0/0",
                        "dimension": "infrastructure_risk"
                    })

            if rtype == "aws_ebs_volume":
                if not re.search(r'encrypted\s*=\s*true', body):
                    violations.append({
                        "rule_id": "TF_EBS_NOT_ENCRYPTED", "file": rel,
                        "resource": res, "severity": "HIGH",
                        "message": "EBS volume missing encryption",
                        "dimension": "infrastructure_risk"
                    })

            if rtype == "aws_db_instance":
                if not re.search(r'storage_encrypted\s*=\s*true', body):
                    violations.append({
                        "rule_id": "TF_RDS_ENCRYPTION_MISSING",
                        "file": rel, "resource": res,
                        "severity": "HIGH",
                        "message": "RDS missing storage_encrypted=true",
                        "dimension": "infrastructure_risk"
                    })

            if rtype in ("aws_sns_topic", "aws_sqs_queue"):
                if not re.search(r'kms_master_key_id', body):
                    violations.append({
                        "rule_id": "TF_SNS_SQS_NO_KMS", "file": rel,
                        "resource": res, "severity": "MEDIUM",
                        "message": f"{rtype} missing KMS encryption",
                        "dimension": "infrastructure_risk"
                    })

    return {"violations": violations, "count": len(violations)}