import jwt
import time
import requests
from config import GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY

class GitHubAppAuth:
    def __init__(self):
        self.app_id = GITHUB_APP_ID
        self.private_key = self._format_private_key(GITHUB_APP_PRIVATE_KEY)
    
    def _format_private_key(self, key):
        """Format the private key properly"""
        if not key:
            return None
            
        # Remove quotes and clean up the key
        key = key.strip().strip('"').strip("'")
        
        # Add proper headers if missing
        if not key.startswith('-----BEGIN'):
            key = f"-----BEGIN RSA PRIVATE KEY-----\n{key}\n-----END RSA PRIVATE KEY-----"
        
        # Replace \n with actual newlines
        key = key.replace('\\n', '\n')
        
        # Ensure proper line breaks (every 64 characters for the key content)
        lines = key.split('\n')
        formatted_lines = []
        
        for line in lines:
            if line.startswith('-----'):
                formatted_lines.append(line)
            else:
                # Split long lines into 64-character chunks
                while len(line) > 64:
                    formatted_lines.append(line[:64])
                    line = line[64:]
                if line:
                    formatted_lines.append(line)
        
        return '\n'.join(formatted_lines)
        
    def generate_jwt_token(self):
        """Generate JWT token for GitHub App authentication"""
        if not self.app_id or not self.private_key:
            raise ValueError("GitHub App ID and Private Key must be configured")
            
        now = int(time.time())
        payload = {
            'iat': now,
            'exp': now + 600,  # 10 minutes
            'iss': self.app_id
        }
        
        try:
            token = jwt.encode(payload, self.private_key, algorithm='RS256')
            return token
        except Exception as e:
            print(f"Private key format issue. First 100 chars: {self.private_key[:100]}...")
            raise e
    
    def get_installation_token(self, installation_id):
        """Get installation access token for a specific installation"""
        jwt_token = self.generate_jwt_token()
        
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
        response = requests.post(url, headers=headers)
        
        if response.status_code == 201:
            return response.json()['token']
        else:
            print(f"❌ Failed to get installation token: {response.status_code}")
            print(f"Response: {response.text}")
            return None
    
    def get_installation_id_from_payload(self, payload):
        """Extract installation ID from webhook payload"""
        return payload.get('installation', {}).get('id')
