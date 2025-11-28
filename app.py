# app.py (updated with PKCE)
from flask import Flask, render_template, request, jsonify, redirect, session
import json
import os
import requests
import hashlib
import base64
import secrets
from config import Config

app = Flask(__name__)
app.secret_key = 'your-secret-key-123-change-in-production'

# PKCE Helper Functions
def generate_code_verifier():
    """Generate a random code verifier for PKCE"""
    return secrets.token_urlsafe(64)

def generate_code_challenge(code_verifier):
    """Generate code challenge from verifier"""
    # SHA-256 hash then base64url encode
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip('=')

class TikTokAPI:
    def __init__(self):
        self.client_key = Config.CLIENT_KEY
        self.client_secret = Config.CLIENT_SECRET
        self.redirect_uri = Config.REDIRECT_URI
    
    def get_auth_url(self):
        """Generate TikTok OAuth URL with PKCE"""
        # Generate PKCE code verifier and challenge
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        
        # Store code_verifier in session for later use
        session['code_verifier'] = code_verifier
        
        auth_url = (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={self.client_key}"
            "&scope=user.info.basic,video.upload,video.list"
            "&response_type=code"
            f"&redirect_uri={self.redirect_uri}"
            "&code_challenge={code_challenge}"
            "&code_challenge_method=S256"
        )
        return auth_url
    
    def exchange_code_for_token(self, auth_code):
        """Exchange authorization code for access token with PKCE"""
        token_url = "https://open.tiktokapis.com/v2/oauth/token/"
        
        # Get the stored code_verifier
        code_verifier = session.get('code_verifier')
        if not code_verifier:
            return {'error': 'Missing code_verifier'}
        
        payload = {
            'client_key': self.client_key,
            'client_secret': self.client_secret,
            'code': auth_code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri,
            'code_verifier': code_verifier
        }
        
        try:
            response = requests.post(token_url, data=payload)
            # Clear the code_verifier from session after use
            session.pop('code_verifier', None)
            return response.json()
        except Exception as e:
            return {'error': str(e)}

tiktok_api = TikTokAPI()

@app.route('/')
def home():
    return """
    <html>
        <head>
            <title>Quran TikTok Uploader</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 800px; margin: 0 auto; }
                .btn { display: inline-block; padding: 12px 24px; background: #FF0050; color: white; 
                      text-decoration: none; border-radius: 8px; font-weight: bold; margin: 10px 0; }
                .card { background: #f9f9f9; padding: 20px; border-radius: 10px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🕌 Quran TikTok Uploader</h1>
                <div class="card">
                    <h2>🚀 Ready to Authenticate</h2>
                    <p>Click below to connect your TikTok account:</p>
                    <a href="/auth" class="btn">🔗 Connect TikTok Account</a>
                </div>
                <div class="card">
                    <h2>📋 Status</h2>
                    <p>✅ Server is running</p>
                    <p>✅ PKCE OAuth configured</p>
                    <p><a href="/status">Check API Status</a></p>
                </div>
            </div>
        </body>
    </html>
    """

@app.route('/auth')
def authenticate():
    """Start TikTok OAuth with PKCE"""
    try:
        auth_url = tiktok_api.get_auth_url()
        return redirect(auth_url)
    except Exception as e:
        return f"Error generating auth URL: {str(e)}"

@app.route('/callback')
def callback():
    """Handle TikTok OAuth callback"""
    auth_code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        return f"❌ OAuth Error: {error}"
    
    if auth_code:
        token_data = tiktok_api.exchange_code_for_token(auth_code)
        
        if 'access_token' in token_data:
            session['access_token'] = token_data['access_token']
            session['refresh_token'] = token_data.get('refresh_token')
            
            return f"""
            <html>
                <head><title>Authentication Successful</title></head>
                <body style="font-family: Arial; margin: 40px;">
                    <h1>✅ Authentication Successful!</h1>
                    <div style="background: #e8f5e8; padding: 20px; border-radius: 8px;">
                        <p><strong>Access Token:</strong> {token_data['access_token'][:50]}...</p>
                        <p><strong>Expires In:</strong> {token_data.get('expires_in', 'Unknown')} seconds</p>
                    </div>
                    <p><a href="/status" style="color: #FF0050;">Check API Status</a></p>
                </body>
            </html>
            """
        else:
            return f"""
            <html>
                <body style="font-family: Arial; margin: 40px;">
                    <h1>❌ Authentication Failed</h1>
                    <pre>{json.dumps(token_data, indent=2)}</pre>
                    <p><a href="/">Try Again</a></p>
                </body>
            </html>
            """
    
    return "No authorization code received"

@app.route('/status')
def api_status():
    """Check API status and user info"""
    access_token = session.get('access_token')
    
    if not access_token:
        return jsonify({
            'authenticated': False,
            'message': 'Please authenticate first'
        })
    
    # Try to get user info to verify token works
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        user_url = "https://open.tiktokapis.com/v2/user/info/"
        response = requests.get(user_url, headers=headers)
        
        if response.status_code == 200:
            user_data = response.json()
            return jsonify({
                'authenticated': True,
                'user_info': user_data,
                'message': 'Successfully connected to TikTok API'
            })
        else:
            return jsonify({
                'authenticated': False,
                'error': response.json(),
                'message': 'Token validation failed'
            })
            
    except Exception as e:
        return jsonify({
            'authenticated': False,
            'error': str(e),
            'message': 'Error connecting to TikTok API'
        })

@app.route('/test')
def test():
    """Test page to verify PKCE is working"""
    return """
    <html>
        <body>
            <h1>PKCE Test</h1>
            <p>Code verifier in session: {}</p>
            <p><a href="/auth">Test OAuth Flow</a></p>
        </body>
    </html>
    """.format('code_verifier' in session)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)