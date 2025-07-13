import requests
import base64
import os
from config import GITHUB_TOKEN
from .app_auth import GitHubAppAuth

GITHUB_API_URL = "https://api.github.com"

# Global auth handler
app_auth = GitHubAppAuth()

def get_headers(installation_id=None):
    """Get appropriate headers for GitHub API calls"""
    if installation_id and app_auth.app_id:
        # Use GitHub App authentication
        token = app_auth.get_installation_token(installation_id)
        if token:
            return {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"
            }
    
    # Fallback to personal access token
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
def get_pr_files(repo_full_name: str, pr_number: int, installation_id=None):
    """
    Fetch list of files changed in a PR.
    Includes patch data (diffs) and optionally full content.
    """
    headers = get_headers(installation_id)
    url = f"{GITHUB_API_URL}/repos/{repo_full_name}/pulls/{pr_number}/files"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"❌ Failed to fetch PR files: {response.status_code}")
        return []

    files = response.json()
    for file in files:
        # Optional: fetch full content for AST analysis
        file["content"] = get_file_content(repo_full_name, file["filename"], installation_id=installation_id)
    return files
def get_file_content(repo: str, path: str, ref="main", installation_id=None):
    """
    Fetch full content of a file at a specific branch/ref.
    Needed for AST-based analysis.
    """
    headers = get_headers(installation_id)
    url = f"{GITHUB_API_URL}/repos/{repo}/contents/{path}?ref={ref}"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return ""

    content_data = response.json()
    return base64.b64decode(content_data["content"]).decode('utf-8')
def post_inline_comment(repo: str, pr_number: int, commit_id: str, filename: str, position: int, body: str, installation_id=None):
    """
    Posts an inline comment on a specific line of a PR diff.
    """
    headers = get_headers(installation_id)
    url = f"{GITHUB_API_URL}/repos/{repo}/pulls/{pr_number}/comments"
    payload = {
        "body": body,
        "commit_id": commit_id,
        "path": filename,
        "position": position  # Line number in the diff
    }

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 201:
        print(f"✅ Comment posted at {filename} line {position}")
    else:
        print(f"❌ Failed to post comment: {response.status_code} {response.text}")
