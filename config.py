import os
from dotenv import load_dotenv

load_dotenv()

# GitHub App Configuration
GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_APP_PRIVATE_KEY = os.getenv("GITHUB_APP_PRIVATE_KEY")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")

# Legacy token support (for backward compatibility)
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_SECRET = os.getenv("GITHUB_SECRET", "")
