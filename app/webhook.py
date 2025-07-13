from flask import Flask, request, jsonify
import hmac
import hashlib
import os
import json

from app.github.api_client import get_pr_files, post_inline_comment
from app.github.app_auth import GitHubAppAuth
from app.analyzer.regex_checker import run_regex_checks
from app.analyzer.ast_checker import run_ast_checks

from config import GITHUB_SECRET, GITHUB_WEBHOOK_SECRET

app = Flask(__name__)
app_auth = GitHubAppAuth()

# GitHub sends raw bytes, so we need to verify using raw data
def verify_github_signature(request):
    signature = request.headers.get('X-Hub-Signature-256')
    if not signature:
        return False

    sha_name, signature = signature.split('=')
    # Use the webhook secret (for GitHub App) or fall back to legacy secret
    secret = GITHUB_WEBHOOK_SECRET or GITHUB_SECRET
    mac = hmac.new(secret.encode(), msg=request.data, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)


@app.route("/webhook", methods=['POST'])
def webhook_listener():
    # 🔐 Signature validation
    if not verify_github_signature(request):
        return jsonify({"error": "Invalid signature"}), 403

    payload = request.json
    print(f"Received payload: {payload}")
    event = request.headers.get("X-GitHub-Event", "ping")

    if event == "ping":
        return jsonify({"message": "pong"}), 200

    # 📦 Only act on pull request opened or synchronized (updated)
    if event == "pull_request" and payload["action"] in ["opened", "synchronize"]:
        pr_data = payload["pull_request"]
        repo = payload["repository"]["full_name"]
        pr_number = payload["number"]
        commit_sha = pr_data["head"]["sha"]
        
        # 🔑 Get installation ID for GitHub App authentication
        installation_id = app_auth.get_installation_id_from_payload(payload)

        print(f"📌 PR #{pr_number} triggered in {repo} — commit: {commit_sha}")

        # 🔽 Get list of changed files in this PR
        changed_files = get_pr_files(repo, pr_number, installation_id)

        for file in changed_files:
            filename = file["filename"]
            if not filename.endswith(".py"):
                continue  # Only analyze Python files for now

            print(f"🔍 Analyzing {filename}")

            raw_code = file["patch"]  # Diff-style content
            full_code = file.get("content")  # Optional: full content if needed

            # 🚨 Run checks
            regex_issues = run_regex_checks(raw_code, filename)
            ast_issues = run_ast_checks(full_code, filename)

            # 📝 Post comments for each issue
            for issue in regex_issues + ast_issues:
                post_inline_comment(
                    repo=repo,
                    pr_number=pr_number,
                    commit_id=commit_sha,
                    filename=filename,
                    position=issue.get("position", issue["line"]),
                    body=issue["message"],
                    installation_id=installation_id
                )

        return jsonify({"message": "Code scan complete ✅"}), 200

    return jsonify({"message": "Ignored event"}), 200
