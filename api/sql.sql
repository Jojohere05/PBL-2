SELECT id, repo, branch, risk_score, decision, created_at
FROM scan_results
ORDER BY id DESC
LIMIT 20;