"""
Context Classifier — determines repo characteristics.

Copied from api/context_classifier.py for standalone CLI usage.
"""

import os

FINTECH_KEYWORDS = [
    "stripe", "razorpay", "payment", "wallet", "loan",
    "kyc", "plaid", "upi", "transaction", "card",
    "bank", "fintech", "neft", "imps", "rtgs"
]

SCAN_EXTENSIONS = (
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".env", ".yaml", ".yml", ".tf", ".json"
)

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def classify_context(repo_path: str) -> dict:
    context = {
        "has_terraform":    False,
        "has_docker":       False,
        "has_vercel":       False,
        "has_dependencies": False,
        "is_fintech":       False,
        "dep_files":        []
    }

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            fpath = os.path.join(root, fname)
            flower = fname.lower()

            if flower.endswith(".tf"):
                context["has_terraform"] = True

            if flower == "dockerfile":
                context["has_docker"] = True

            if flower in ("vercel.json", "next.config.js"):
                context["has_vercel"] = True

            if flower in ("requirements.txt", "package.json"):
                context["has_dependencies"] = True
                context["dep_files"].append(fpath)

            # Fintech keyword scan — only in relevant extensions
            if not context["is_fintech"] and \
                    flower.endswith(SCAN_EXTENSIONS):
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        content = f.read(50_000).lower()  # max 50KB
                    if any(kw in content for kw in FINTECH_KEYWORDS):
                        context["is_fintech"] = True
                except Exception:
                    pass

    return context
