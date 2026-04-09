"""
Terraform Agent — scans .tf files for misconfigurations.

Copied from api/adk_agents/terraform_agent.py for standalone CLI usage.
"""

import os
import re

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def _extract_blocks(content: str) -> list:
    results = []

    for m in re.finditer(
        r'(resource|module)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{',
        content
    ):
        block_type = m.group(1)
        name1 = m.group(2)
        name2 = m.group(3) or ""

        if block_type == "resource":
            rtype, rname = name1, name2
        else:
            rtype, rname = "module", name1

        start, depth, i = m.end(), 1, m.end()

        while i < len(content) and depth > 0:
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
            i += 1

        results.append((rtype, rname, content[start:i - 1]))

    return results


def scan_terraform_files(repo_path: str) -> dict:
    violations = []
    tf_files = []

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

            # STRICT MISCONFIGS
            if re.search(r'publicly_accessible\s*=\s*true', body):
                violations.append({
                    "rule_id": "TF_DB_PUBLIC",
                    "file": rel,
                    "resource": res,
                    "severity": "CRITICAL",
                    "message": "Database is publicly accessible",
                    "dimension": "infrastructure_risk"
                })

            if re.search(r'storage_encrypted\s*=\s*false', body):
                violations.append({
                    "rule_id": "TF_STORAGE_UNENCRYPTED",
                    "file": rel,
                    "resource": res,
                    "severity": "HIGH",
                    "message": "Storage encryption disabled",
                    "dimension": "infrastructure_risk"
                })

            # MISSING CONFIG DETECTION
            if rtype == "aws_db_instance":
                if "storage_encrypted" not in body:
                    violations.append({
                        "rule_id": "TF_RDS_ENCRYPTION_NOT_DEFINED",
                        "file": rel,
                        "resource": res,
                        "severity": "MEDIUM",
                        "message": "RDS encryption not explicitly defined",
                        "dimension": "infrastructure_risk"
                    })

            if "s3_bucket" in rtype:
                if "block_public_acls" not in body:
                    violations.append({
                        "rule_id": "TF_S3_PUBLIC_BLOCK_NOT_DEFINED",
                        "file": rel,
                        "resource": res,
                        "severity": "MEDIUM",
                        "message": "S3 public access block not configured",
                        "dimension": "infrastructure_risk"
                    })

                if re.search(r'acl\s*=\s*"public-read', body):
                    violations.append({
                        "rule_id": "TF_S3_PUBLIC_ACL",
                        "file": rel,
                        "resource": res,
                        "severity": "CRITICAL",
                        "message": "S3 bucket public-read ACL",
                        "dimension": "infrastructure_risk"
                    })

            # SECURITY GROUP
            if "security_group" in rtype:
                if "cidr_blocks" in body:
                    if "0.0.0.0/0" in body:
                        violations.append({
                            "rule_id": "TF_SG_OPEN_INGRESS",
                            "file": rel,
                            "resource": res,
                            "severity": "HIGH",
                            "message": "Security group allows 0.0.0.0/0",
                            "dimension": "infrastructure_risk"
                        })
                    else:
                        violations.append({
                            "rule_id": "TF_SG_DYNAMIC_CIDR",
                            "file": rel,
                            "resource": res,
                            "severity": "LOW",
                            "message": "Security group uses dynamic CIDR — review required",
                            "dimension": "infrastructure_risk"
                        })

            # EBS
            if rtype == "aws_ebs_volume":
                if "encrypted" not in body:
                    violations.append({
                        "rule_id": "TF_EBS_ENCRYPTION_NOT_DEFINED",
                        "file": rel,
                        "resource": res,
                        "severity": "MEDIUM",
                        "message": "EBS encryption not explicitly defined",
                        "dimension": "infrastructure_risk"
                    })

            # SNS/SQS
            if rtype in ("aws_sns_topic", "aws_sqs_queue"):
                if "kms_master_key_id" not in body:
                    violations.append({
                        "rule_id": "TF_SNS_SQS_NO_KMS",
                        "file": rel,
                        "resource": res,
                        "severity": "MEDIUM",
                        "message": f"{rtype} missing KMS encryption",
                        "dimension": "infrastructure_risk"
                    })

    return {"violations": violations, "count": len(violations)}
