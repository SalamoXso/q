# app.py - Complete version with SDK authentication and fallbacks
from flask import Flask, render_template, request, jsonify, redirect, session
import json
import os
import requests
import hashlib
import base64
import secrets
from config import Config

app = Flask(__name__)
app.secret_key = 'your-secret-key-123-change-in-production-for-tiktok-sandbox'

# Determine if we're running locally or on Render
IS_RENDER = 'RENDER' in os.environ

if IS_RENDER:
    print("🚀 Running on Render (Production)")
else:
    print("💻 Running locally (Sandbox Testing)")

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
        print(f"🔧 TikTok API Config - Client Key: {self.client_key[:10]}..., Redirect: {self.redirect_uri}")
    
    def get_auth_url(self):
        """Generate TikTok OAuth URL with PKCE"""
        try:
            # Generate PKCE code verifier and challenge
            code_verifier = generate_code_verifier()
            code_challenge = generate_code_challenge(code_verifier)
            
            # Store code_verifier in session for later use
            session['code_verifier'] = code_verifier
            session['code_challenge'] = code_challenge
            
            # Use raw redirect_uri (no encoding)
            auth_url = (
                f"https://www.tiktok.com/v2/auth/authorize/"
                f"?client_key={self.client_key}"
                "&scope=user.info.basic,video.upload,video.list"
                "&response_type=code"
                f"&redirect_uri={self.redirect_uri}"
                f"&code_challenge={code_challenge}"
                "&code_challenge_method=S256"
            )
            print(f"🔗 Generated Auth URL: {auth_url}")
            return auth_url
        except Exception as e:
            print(f"❌ Error generating auth URL: {e}")
            raise e
    
    def exchange_code_for_token(self, auth_code):
        """Exchange authorization code for access token with PKCE"""
        token_url = "https://open.tiktokapis.com/v2/oauth/token/"
        
        # Get the stored code_verifier
        code_verifier = session.get('code_verifier')
        if not code_verifier:
            error_msg = 'Missing code_verifier in session'
            print(f"❌ {error_msg}")
            return {'error': error_msg}
        
        print(f"🔄 Exchanging code for token, code_verifier: {code_verifier[:20]}...")
        
        payload = {
            'client_key': self.client_key,
            'client_secret': self.client_secret,
            'code': auth_code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri,
            'code_verifier': code_verifier
        }
        
        try:
            print(f"📤 Making token request to: {token_url}")
            response = requests.post(token_url, data=payload)
            print(f"📥 Token response status: {response.status_code}")
            print(f"📥 Token response: {response.text}")
            
            # Clear the code_verifier from session after use
            session.pop('code_verifier', None)
            session.pop('code_challenge', None)
            
            return response.json()
        except Exception as e:
            error_msg = f'Token exchange failed: {str(e)}'
            print(f"❌ {error_msg}")
            return {'error': error_msg}

# Initialize TikTok API
tiktok_api = TikTokAPI()

@app.route('/')
def home():
    """Main dashboard"""
    environment = "Production" if IS_RENDER else "Sandbox (Local Testing)"
    access_token = session.get('access_token')
    authenticated = bool(access_token)
    
    return f"""
    <html>
        <head>
            <title>Quran TikTok Uploader - {environment}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
                .container {{ max-width: 800px; margin: 0 auto; }}
                .card {{ background: #f9f9f9; padding: 25px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #FF0050; }}
                .btn {{ display: inline-block; padding: 14px 28px; background: #FF0050; color: white; 
                      text-decoration: none; border-radius: 8px; font-weight: bold; margin: 10px 5px 10px 0; 
                      transition: background 0.3s; }}
                .btn:hover {{ background: #e00040; }}
                .btn-secondary {{ background: #666; }}
                .btn-secondary:hover {{ background: #555; }}
                .btn-success {{ background: #28a745; }}
                .btn-success:hover {{ background: #218838; }}
                .status {{ padding: 10px; border-radius: 6px; margin: 10px 0; }}
                .status-success {{ background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
                .status-warning {{ background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }}
                .info-box {{ background: #d1ecf1; color: #0c5460; padding: 15px; border-radius: 6px; margin: 15px 0; }}
                .warning-box {{ background: #f8d7da; color: #721c24; padding: 15px; border-radius: 6px; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🕌 Quran TikTok Uploader</h1>
                
                <div class="warning-box">
                    <h3>⚠️ OAuth Page Issues Detected</h3>
                    <p>TikTok's OAuth page has JavaScript compatibility problems. Use the <strong>SDK Authentication</strong> below instead.</p>
                </div>
                
                <div class="card">
                    <h2>📊 System Status</h2>
                    <div class="status {'status-success' if authenticated else 'status-warning'}">
                        <strong>Authentication:</strong> {'✅ Authenticated' if authenticated else '❌ Not Authenticated'}
                    </div>
                    <p><strong>Environment:</strong> {environment}</p>
                    <p><strong>Redirect URI:</strong> {Config.REDIRECT_URI}</p>
                    <p><strong>Client Key:</strong> {Config.CLIENT_KEY[:10]}...</p>
                </div>

                <div class="card">
                    <h2>🚀 Recommended Authentication Methods</h2>
                    <a href="/sdk-auth" class="btn btn-success">🔗 SDK Authentication (Recommended)</a>
                    <a href="/mobile-forced-auth" class="btn">📱 Mobile-Forced Auth</a>
                    <a href="/manual-token-setup" class="btn btn-secondary">🔧 Manual Setup</a>
                </div>

                <div class="card">
                    <h2>📡 Other Actions</h2>
                    <a href="/status" class="btn btn-secondary">📡 Check API Status</a>
                    <a href="/debug" class="btn btn-secondary">🐛 Debug Info</a>
                    <a href="/auth" class="btn btn-secondary">🔄 Original OAuth (Broken)</a>
                </div>

                {f'''
                <div class="card">
                    <h2>✅ Authentication Successful</h2>
                    <p>Your TikTok account is connected and ready for testing.</p>
                    <p><strong>Access Token:</strong> {access_token[:50]}...</p>
                    <a href="/test-upload" class="btn">🎬 Test Video Upload</a>
                </div>
                ''' if authenticated else ''}

                <div class="info-box">
                    <h3>💡 Why Use SDK Authentication?</h3>
                    <p>TikTok's standard OAuth page has JavaScript errors that break authentication. The SDK approach:</p>
                    <ul>
                        <li>✅ Uses TikTok's official JavaScript (more stable)</li>
                        <li>✅ Avoids broken OAuth page entirely</li>
                        <li>✅ Better error handling and user experience</li>
                        <li>✅ Same security and functionality</li>
                    </ul>
                </div>
            </div>
        </body>
    </html>
    """

@app.route('/auth')
def authenticate():
    """Original OAuth (currently broken due to TikTok JS issues)"""
    try:
        print("🔄 Starting OAuth flow...")
        auth_url = tiktok_api.get_auth_url()
        print(f"🔗 Redirecting to: {auth_url}")
        return redirect(auth_url)
    except Exception as e:
        error_msg = f"Error generating auth URL: {str(e)}"
        print(f"❌ {error_msg}")
        return f"""
        <html>
            <body style="font-family: Arial; margin: 40px;">
                <h1>❌ Authentication Error</h1>
                <div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 8px;">
                    <p><strong>Error:</strong> {error_msg}</p>
                </div>
                <p><a href="/">← Back to Home</a></p>
            </body>
        </html>
        """

@app.route('/callback')
def callback():
    """Handle TikTok OAuth callback"""
    auth_code = request.args.get('code')
    error = request.args.get('error')
    error_description = request.args.get('error_description')
    
    print(f"📥 Callback received - code: {auth_code}, error: {error}")
    
    if error:
        error_msg = f"OAuth Error: {error}"
        if error_description:
            error_msg += f" - {error_description}"
        print(f"❌ {error_msg}")
        return f"""
        <html>
            <body style="font-family: Arial; margin: 40px;">
                <h1>❌ OAuth Error</h1>
                <div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 8px;">
                    <p><strong>Error:</strong> {error}</p>
                    <p><strong>Description:</strong> {error_description}</p>
                </div>
                <p><a href="/">← Back to Home</a></p>
            </body>
        </html>
        """
    
    if auth_code:
        print(f"🔄 Exchanging authorization code: {auth_code}")
        token_data = tiktok_api.exchange_code_for_token(auth_code)
        
        if 'access_token' in token_data:
            session['access_token'] = token_data['access_token']
            session['refresh_token'] = token_data.get('refresh_token')
            session['expires_in'] = token_data.get('expires_in')
            
            print(f"✅ Authentication successful! Access token: {token_data['access_token'][:50]}...")
            
            return f"""
            <html>
                <head>
                    <title>Authentication Successful</title>
                    <style>
                        body {{ font-family: Arial; margin: 40px; }}
                        .success {{ background: #d4edda; color: #155724; padding: 20px; border-radius: 8px; }}
                    </style>
                </head>
                <body>
                    <h1>✅ Authentication Successful!</h1>
                    <div class="success">
                        <p><strong>Access Token:</strong> {token_data['access_token'][:50]}...</p>
                        <p><strong>Expires In:</strong> {token_data.get('expires_in', 'Unknown')} seconds</p>
                        <p><strong>Scope:</strong> {token_data.get('scope', 'Unknown')}</p>
                    </div>
                    <p><a href="/">🏠 Go to Dashboard</a> | <a href="/status">📡 Check API Status</a></p>
                </body>
            </html>
            """
        else:
            error_msg = f"Token exchange failed: {token_data}"
            print(f"❌ {error_msg}")
            return f"""
            <html>
                <body style="font-family: Arial; margin: 40px;">
                    <h1>❌ Authentication Failed</h1>
                    <div style="background: #f8d7da; color: #721c24; padding: 20px; border-radius: 8px;">
                        <pre>{json.dumps(token_data, indent=2)}</pre>
                    </div>
                    <p><a href="/">← Try Again</a></p>
                </body>
            </html>
            """
    
    return """
    <html>
        <body style="font-family: Arial; margin: 40px;">
            <h1>❌ No Authorization Code</h1>
            <p>No authorization code was received from TikTok.</p>
            <p><a href="/">← Back to Home</a></p>
        </body>
    </html>
    """

@app.route('/sdk-auth')
def sdk_auth():
    """Use TikTok's JavaScript SDK for authentication"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>TikTok SDK Authentication</title>
        <script src="https://js-sdk.tiktok.com/platform.js"></script>
    </head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>🔄 TikTok SDK Authentication</h1>
        <p>Using TikTok's official JavaScript SDK to avoid OAuth page issues.</p>
        
        <div id="tiktok-login" style="margin: 20px 0;">
            <button onclick="authenticateWithSDK()" style="padding: 15px 30px; background: #FF0050; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer;">
                🔗 Login with TikTok SDK
            </button>
        </div>
        
        <div id="status" style="padding: 15px; border-radius: 5px; display: none;"></div>

        <script>
            // Initialize TikTok SDK
            function authenticateWithSDK() {
                const status = document.getElementById('status');
                status.style.display = 'block';
                status.innerHTML = '<p>🔄 Initializing TikTok SDK...</p>';
                
                // TikTok SDK authentication
                window.tt.login({
                    scope: 'user.info.basic',
                    redirectUri: 'http://127.0.0.1:5000/sdk-callback',
                    state: 'quran-app-state'
                }, function(response) {
                    console.log('SDK Response:', response);
                    
                    if (response.authCode) {
                        status.innerHTML = '<p style="color: green;">✅ SDK Authentication Successful!</p>';
                        status.innerHTML += '<p>Auth Code: ' + response.authCode + '</p>';
                        
                        // Send the auth code to our backend
                        fetch('/exchange-sdk-token', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                authCode: response.authCode
                            })
                        })
                        .then(response => response.json())
                        .then(data => {
                            if (data.access_token) {
                                status.innerHTML += '<p style="color: green;">✅ Token Exchange Successful!</p>';
                                status.innerHTML += '<p>Access Token: ' + data.access_token.substring(0, 50) + '...</p>';
                                status.innerHTML += '<p><a href="/">Go to Dashboard</a></p>';
                            } else {
                                status.innerHTML += '<p style="color: red;">❌ Token Exchange Failed: ' + JSON.stringify(data) + '</p>';
                            }
                        });
                    } else {
                        status.innerHTML = '<p style="color: red;">❌ SDK Authentication Failed: ' + JSON.stringify(response) + '</p>';
                    }
                });
            }
            
            // Check if SDK loaded
            document.addEventListener('DOMContentLoaded', function() {
                const status = document.getElementById('status');
                if (typeof window.tt !== 'undefined') {
                    status.innerHTML = '<p style="color: green;">✅ TikTok SDK Loaded Successfully</p>';
                } else {
                    status.innerHTML = '<p style="color: red;">❌ TikTok SDK Failed to Load</p>';
                }
            });
        </script>
        
        <div style="margin-top: 30px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
            <h3>Why SDK Approach?</h3>
            <p>TikTok's OAuth page has JavaScript compatibility issues that break the redirect flow. The SDK approach:</p>
            <ul>
                <li>✅ Uses TikTok's official JavaScript</li>
                <li>✅ Avoids broken OAuth page</li>
                <li>✅ Handles authentication in background</li>
                <li>✅ Better error handling</li>
            </ul>
        </div>
    </body>
    </html>
    """

@app.route('/exchange-sdk-token', methods=['POST'])
def exchange_sdk_token():
    """Exchange SDK auth code for access token"""
    try:
        data = request.json
        auth_code = data.get('authCode')
        
        if not auth_code:
            return jsonify({'error': 'No auth code provided'})
        
        # Exchange auth code for access token
        token_url = "https://open.tiktokapis.com/v2/oauth/token/"
        payload = {
            'client_key': Config.CLIENT_KEY,
            'client_secret': Config.CLIENT_SECRET,
            'code': auth_code,
            'grant_type': 'authorization_code',
            'redirect_uri': 'http://127.0.0.1:5000/sdk-callback'
        }
        
        response = requests.post(token_url, data=payload)
        token_data = response.json()
        
        if 'access_token' in token_data:
            # Store in session
            session['access_token'] = token_data['access_token']
            return jsonify(token_data)
        else:
            return jsonify(token_data)
            
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/sdk-callback')
def sdk_callback():
    """Callback for SDK authentication"""
    return """
    <html>
    <body style="font-family: Arial; margin: 40px;">
        <h1>✅ SDK Authentication Complete</h1>
        <p>The TikTok SDK authentication has completed. You can close this window and return to the main app.</p>
        <p><a href="/sdk-auth">Back to SDK Auth</a> | <a href="/">Main Dashboard</a></p>
    </body>
    </html>
    """

@app.route('/mobile-forced-auth')
def mobile_forced_auth():
    """Force mobile user agent to avoid desktop JS issues"""
    auth_url = (
        f"https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={Config.CLIENT_KEY}"
        "&scope=user.info.basic"
        "&response_type=code"
        f"&redirect_uri={Config.REDIRECT_URI}"
    )
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Mobile-Forced Authentication</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <script>
            // Force mobile user agent
            Object.defineProperty(navigator, 'userAgent', {{
                get: function() {{
                    return 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1';
                }}
            }});
            
            // Redirect to TikTok auth
            window.location.href = "{auth_url}";
        </script>
    </head>
    <body>
        <h2>📱 Redirecting to Mobile-Optimized TikTok Auth...</h2>
        <p>If not redirected, <a href="{auth_url}">click here</a>.</p>
    </body>
    </html>
    """

@app.route('/manual-token-setup')
def manual_token_setup():
    """Manual token setup when OAuth is completely broken"""
    return """
    <html>
    <head>
        <title>Manual Token Setup</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            .card { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
        </style>
    </head>
    <body>
        <h1>🔧 Manual Token Setup</h1>
        
        <div class="card">
            <h3>When OAuth is Broken</h3>
            <p>Since TikTok's OAuth page has JavaScript issues, you can manually set up tokens:</p>
            
            <h4>Option 1: Use TikTok's Testing Tools</h4>
            <ol>
                <li>Go to <a href="https://developers.tiktok.com/tools/test/oauth/" target="_blank">TikTok OAuth Tester</a></li>
                <li>Use your Client Key</li>
                <li>Set redirect_uri to: <code>http://127.0.0.1:5000/callback</code></li>
                <li>Get the authorization code</li>
                <li>Paste it below</li>
            </ol>
            
            <h4>Option 2: Manual Token Entry</h4>
            <form action="/set-manual-token" method="post">
                <p><strong>Access Token:</strong></p>
                <input type="text" name="access_token" style="width: 100%; padding: 10px; margin: 10px 0;" placeholder="Paste access token here">
                <button type="submit" style="padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px;">
                    Set Manual Token
                </button>
            </form>
        </div>
        
        <p><a href="/">← Back to Main Dashboard</a></p>
    </body>
    </html>
    """

@app.route('/set-manual-token', methods=['POST'])
def set_manual_token():
    """Set manually obtained token"""
    access_token = request.form.get('access_token')
    if access_token:
        session['access_token'] = access_token
        return """
        <html>
        <body style="font-family: Arial; margin: 40px;">
            <h1 style="color: green;">✅ Manual Token Set Successfully</h1>
            <p>Your access token has been stored in the session.</p>
            <p><a href="/status">Check API Status</a> | <a href="/">Main Dashboard</a></p>
        </body>
        </html>
        """
    else:
        return "No token provided"

@app.route('/status')
def api_status():
    """Check API status and user info"""
    access_token = session.get('access_token')
    
    if not access_token:
        return jsonify({
            'authenticated': False,
            'message': 'Please authenticate first',
            'environment': 'Sandbox' if not IS_RENDER else 'Production'
        })
    
    # Try to get user info to verify token works
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        user_url = "https://open.tiktokapis.com/v2/user/info/"
        print(f"📤 Checking user info with token: {access_token[:50]}...")
        response = requests.get(user_url, headers=headers)
        
        if response.status_code == 200:
            user_data = response.json()
            print(f"✅ User info retrieved successfully")
            return jsonify({
                'authenticated': True,
                'user_info': user_data,
                'message': 'Successfully connected to TikTok API',
                'environment': 'Sandbox' if not IS_RENDER else 'Production'
            })
        else:
            error_data = response.json()
            print(f"❌ User info failed: {error_data}")
            return jsonify({
                'authenticated': False,
                'error': error_data,
                'message': 'Token validation failed',
                'environment': 'Sandbox' if not IS_RENDER else 'Production'
            })
            
    except Exception as e:
        print(f"❌ Error checking user info: {e}")
        return jsonify({
            'authenticated': False,
            'error': str(e),
            'message': 'Error connecting to TikTok API',
            'environment': 'Sandbox' if not IS_RENDER else 'Production'
        })

@app.route('/debug')
def debug_config():
    """Debug page to check configuration"""
    config_status = {
        'environment': 'Production' if IS_RENDER else 'Sandbox',
        'client_key_set': bool(Config.CLIENT_KEY) and Config.CLIENT_KEY != 'your_client_key_here',
        'client_secret_set': bool(Config.CLIENT_SECRET) and Config.CLIENT_SECRET != 'your_client_secret_here',
        'redirect_uri': Config.REDIRECT_URI,
        'expected_redirect_uri': 'http://127.0.0.1:5000/callback',
        'redirect_uri_match': Config.REDIRECT_URI == 'http://127.0.0.1:5000/callback',
        'session_keys': list(session.keys()),
        'has_access_token': 'access_token' in session,
        'has_code_verifier': 'code_verifier' in session,
        'has_code_challenge': 'code_challenge' in session
    }
    
    return jsonify(config_status)

@app.route('/test-upload')
def test_upload():
    """Test upload page"""
    access_token = session.get('access_token')
    if not access_token:
        return redirect('/auth')
    
    return """
    <html>
        <head>
            <title>Test Upload - Quran TikTok</title>
            <style>
                body { font-family: Arial; margin: 40px; }
                .card { background: #f9f9f9; padding: 20px; border-radius: 8px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <h1>🎬 Test Video Upload</h1>
            <div class="card">
                <h2>Sandbox Upload Testing</h2>
                <p>In sandbox mode, video upload functionality might be limited or simulated.</p>
                <p><strong>Note:</strong> Full upload functionality will be available when we move to production.</p>
            </div>
            <p><a href="/">← Back to Dashboard</a></p>
        </body>
    </html>
    """

@app.route('/clear-session')
def clear_session():
    """Clear session data (for testing)"""
    session.clear()
    return """
    <html>
        <body style="font-family: Arial; margin: 40px;">
            <h1>🧹 Session Cleared</h1>
            <p>All session data has been cleared.</p>
            <p><a href="/">← Back to Home</a></p>
        </body>
    </html>
    """

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('videos/raw', exist_ok=True)
    os.makedirs('videos/processed', exist_ok=True)
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    
    print(f"🚀 Starting Flask server on port {port}")
    print(f"🔧 Debug mode: {debug}")
    print(f"🌐 Redirect URI: {Config.REDIRECT_URI}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)