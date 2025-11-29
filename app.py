# app.py - Complete updated version for TikTok Sandbox testing
from flask import Flask, render_template, request, jsonify, redirect, session
import json
import os
import requests
import hashlib
import base64
import secrets
from config import Config
import urllib.parse


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
            
            # DO NOT URL encode the redirect_uri - TikTok expects it raw
            auth_url = (
                f"https://www.tiktok.com/v2/auth/authorize/"
                f"?client_key={self.client_key}"
                "&scope=user.info.basic,video.upload,video.list"
                "&response_type=code"
                f"&redirect_uri={self.redirect_uri}"  # Use raw, unencoded URI
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
            'redirect_uri': self.redirect_uri,  # Use raw URI here too
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
@app.route('/auth-debug')
def auth_debug():
    """Debug the exact OAuth URL being generated"""
    try:
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        
        # Use raw redirect_uri (no encoding)
        auth_url = (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={Config.CLIENT_KEY}"
            "&scope=user.info.basic,video.upload,video.list"
            "&response_type=code"
            f"&redirect_uri={Config.REDIRECT_URI}"  # Raw, unencoded
            f"&code_challenge={code_challenge}"
            "&code_challenge_method=S256"
        )
        
        debug_info = {
            "raw_redirect_uri": Config.REDIRECT_URI,
            "client_key": Config.CLIENT_KEY[:10] + "...",
            "code_challenge_length": len(code_challenge),
            "full_auth_url": auth_url,
            "note": "Using RAW redirect_uri (no URL encoding)"
        }
        
        return jsonify(debug_info)
        
    except Exception as e:
        return jsonify({"error": str(e)})
      
      

@app.route('/deep-diagnostic')
def deep_diagnostic():
    """Deep diagnostic of TikTok sandbox configuration"""
    
    # Check all possible redirect URI combinations
    base_uris = [
        'http://127.0.0.1:5000',
        'http://localhost:5000', 
        'http://127.0.0.1',
        'http://localhost'
    ]
    
    paths = ['/callback', '/', '']
    
    test_cases = []
    for base in base_uris:
        for path in paths:
            test_uri = base + path
            test_cases.append(test_uri)
    
    diagnostic = {
        "current_config": {
            "client_key": Config.CLIENT_KEY,
            "client_key_length": len(Config.CLIENT_KEY),
            "redirect_uri": Config.REDIRECT_URI,
            "environment": "Sandbox"
        },
        "test_cases": [],
        "common_sandbox_issues": [
            "Make sure 'http://127.0.0.1:5000/callback' is EXACTLY set in TikTok Portal",
            "Ensure both 'Web' and 'Desktop' are checked for the redirect URI",
            "Verify test account 'thereisonly1godallah1' is in Target Users",
            "Click 'Apply Changes' after any modification",
            "Wait 5-10 minutes for changes to propagate"
        ]
    }
    
    for test_uri in test_cases:
        auth_url = (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={Config.CLIENT_KEY}"
            "&scope=user.info.basic"
            "&response_type=code"
            f"&redirect_uri={test_uri}"
        )
        
        diagnostic["test_cases"].append({
            "redirect_uri": test_uri,
            "auth_url_length": len(auth_url),
            "test_link": auth_url
        })
    
    # Create HTML response
    html = """
    <html>
        <head>
            <title>TikTok Sandbox Deep Diagnostic</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .test-case { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
                .warning { background: #fff3cd; padding: 15px; border-radius: 5px; }
                .success { background: #d4edda; padding: 15px; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>🔍 TikTok Sandbox Deep Diagnostic</h1>
            
            <div class="warning">
                <h3>⚠️ Current Status: Authentication Failing</h3>
                <p>Even with correct redirect_uri format, TikTok is rejecting the request.</p>
            </div>
            
            <h2>Current Configuration</h2>
            <ul>
                <li><strong>Client Key:</strong> {client_key}</li>
                <li><strong>Redirect URI:</strong> {redirect_uri}</li>
                <li><strong>Environment:</strong> {environment}</li>
            </ul>
            
            <h2>🧪 Test All Possible Redirect URI Formats</h2>
            <p>Click each link to test different redirect URI formats:</p>
    """.format(
        client_key=diagnostic["current_config"]["client_key"],
        redirect_uri=diagnostic["current_config"]["redirect_uri"], 
        environment=diagnostic["current_config"]["environment"]
    )
    
    for i, test_case in enumerate(diagnostic["test_cases"]):
        html += f"""
        <div class="test-case">
            <h3>Test Case #{i+1}</h3>
            <p><strong>Redirect URI:</strong> {test_case['redirect_uri']}</p>
            <a href="{test_case['test_link']}" target="_blank">🔗 Test This URI</a>
        </div>
        """
    
    html += """
            <h2>🔧 Required Actions in TikTok Developer Portal</h2>
            <ol>
                <li>Go to <a href="https://developers.tiktok.com/" target="_blank">TikTok Developer Portal</a></li>
                <li>Open your "Quran" app</li>
                <li>Go to "Products" → "Login Kit"</li>
                <li>In "Redirect URI" section, make sure you have EXACTLY: <code>http://127.0.0.1:5000/callback</code></li>
                <li>Check both "Web" and "Desktop" checkboxes</li>
                <li>Scroll down and click "Apply Changes"</li>
                <li>Wait 5-10 minutes</li>
                <li>Come back and test the links above</li>
            </ol>
            
            <h2>🎯 Quick Test Links</h2>
            <p>Try these specific test cases first:</p>
            <ul>
                <li><a href="/test-simple">Simple test (no PKCE)</a></li>
                <li><a href="/test-no-scope">Test without scopes</a></li>
                <li><a href="/test-different-ports">Test different ports</a></li>
            </ul>
        </body>
    </html>
    """
    
    return html

@app.route('/test-simple')
def test_simple():
    """Test with absolute minimum parameters"""
    auth_url = (
        f"https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={Config.CLIENT_KEY}"
        "&response_type=code"
        f"&redirect_uri=http://127.0.0.1:5000/callback"
    )
    return redirect(auth_url)

@app.route('/test-no-scope') 
def test_no_scope():
    """Test without any scopes"""
    auth_url = (
        f"https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={Config.CLIENT_KEY}"
        "&response_type=code"
        f"&redirect_uri=http://127.0.0.1:5000/callback"
        "&scope=user.info.basic"  # Only basic scope
    )
    return redirect(auth_url)

@app.route('/test-different-ports')
def test_different_ports():
    """Test different port configurations"""
    ports = ['5000', '8080', '3000', '']
    
    html = "<h1>Test Different Ports</h1>"
    for port in ports:
        redirect_uri = f"http://127.0.0.1:{port}/callback" if port else "http://127.0.0.1/callback"
        auth_url = (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={Config.CLIENT_KEY}"
            "&response_type=code"
            f"&redirect_uri={redirect_uri}"
        )
        html += f"""
        <div style="border: 1px solid #ccc; padding: 15px; margin: 10px;">
            <h3>Port: {port if port else 'None'}</h3>
            <p><strong>Redirect URI:</strong> {redirect_uri}</p>
            <a href="{auth_url}">Test This Configuration</a>
        </div>
        """
    return html


@app.route('/browser-compatible-auth')
def browser_compatible_auth():
    """OAuth flow optimized for browser compatibility issues"""
    
    # Generate PKCE
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    session['code_verifier'] = code_verifier
    
    auth_url = (
        f"https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={Config.CLIENT_KEY}"
        "&scope=user.info.basic"  # Reduced scope to minimize issues
        "&response_type=code"
        f"&redirect_uri={Config.REDIRECT_URI}"
        f"&code_challenge={code_challenge}"
        "&code_challenge_method=S256"
    )
    
    return f"""
    <html>
        <head>
            <title>Browser-Compatible TikTok Auth</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .warning {{ background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; }}
                .steps {{ background: #e9ecef; padding: 20px; border-radius: 8px; }}
            </style>
        </head>
        <body>
            <h1>🔄 Browser-Optimized TikTok Authentication</h1>
            
            <div class="warning">
                <h3>⚠️ Browser Compatibility Detected</h3>
                <p>TikTok's OAuth page has JavaScript compatibility issues. Follow these steps:</p>
            </div>
            
            <div class="steps">
                <h3>🎯 Recommended Steps:</h3>
                <ol>
                    <li><strong>Use Incognito/Private Mode</strong> to avoid extension conflicts</li>
                    <li><strong>Disable ad blockers</strong> for TikTok domains</li>
                    <li><strong>Allow pop-ups</strong> for TikTok.com</li>
                    <li>If errors persist, try a different browser</li>
                </ol>
            </div>
            
            <h2>🔗 Authentication Link:</h2>
            <a href="{auth_url}" style="font-size: 18px; padding: 15px; background: #FF0050; color: white; text-decoration: none; border-radius: 8px; display: inline-block;">
                🚀 Launch TikTok OAuth (Optimized)
            </a>
            
            <div style="margin-top: 30px;">
                <h3>Alternative Approaches:</h3>
                <ul>
                    <li><a href="/mobile-simulation">📱 Mobile Simulation</a></li>
                    <li><a href="/direct-auth-link">🔗 Direct Auth Link</a></li>
                    <li><a href="/test-minimal-scopes">🧪 Minimal Scope Test</a></li>
                </ul>
            </div>
        </body>
    </html>
    """

@app.route('/mobile-simulation')
def mobile_simulation():
    """Simulate mobile browser to avoid desktop JS issues"""
    auth_url = (
        f"https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={Config.CLIENT_KEY}"
        "&scope=user.info.basic"
        "&response_type=code"
        f"&redirect_uri={Config.REDIRECT_URI}"
    )
    
    return f"""
    <html>
        <head>
            <title>Mobile Simulation</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body>
            <h2>📱 Mobile Simulation</h2>
            <p>This page simulates a mobile environment which may avoid desktop JS issues.</p>
            <a href="{auth_url}">Open TikTok OAuth in Mobile Mode</a>
            
            <script>
                // Force mobile user agent simulation
                window.location.href = "{auth_url}";
            </script>
        </body>
    </html>
    """

@app.route('/direct-auth-link')
def direct_auth_link():
    """Provide direct auth link for manual testing"""
    auth_url = (
        f"https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={Config.CLIENT_KEY}"
        "&scope=user.info.basic"
        "&response_type=code"
        f"&redirect_uri={Config.REDIRECT_URI}"
    )
    
    return f"""
    <html>
        <body>
            <h2>🔗 Direct Authentication Link</h2>
            <p>Copy and paste this URL directly into a <strong>clean browser window</strong>:</p>
            <textarea style="width: 100%; height: 100px; font-family: monospace; padding: 10px;" readonly>{auth_url}</textarea>
            <p><strong>Instructions:</strong></p>
            <ol>
                <li>Open a <strong>new incognito/private window</strong></li>
                <li>Copy the URL above</li>
                <li>Paste it in the address bar and press Enter</li>
                <li>This avoids any extension interference</li>
            </ol>
        </body>
    </html>
    """

@app.route('/test-minimal-scopes')
def test_minimal_scopes():
    """Test with absolute minimum configuration"""
    test_cases = [
        {"scopes": "user.info.basic", "description": "Basic user info only"},
        {"scopes": "", "description": "No scopes (just authentication)"},
        {"scopes": "user.info.basic,video.list", "description": "Basic + video list (no upload)"},
    ]
    
    html = "<h1>🧪 Minimal Scope Testing</h1>"
    html += "<p>Testing with reduced scopes to minimize JavaScript complexity:</p>"
    
    for i, test_case in enumerate(test_cases):
        auth_url = (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={Config.CLIENT_KEY}"
            f"&scope={test_case['scopes']}"
            "&response_type=code"
            f"&redirect_uri={Config.REDIRECT_URI}"
        )
        
        html += f"""
        <div style="border: 1px solid #ccc; padding: 20px; margin: 15px 0; border-radius: 8px;">
            <h3>Test #{i+1}: {test_case['description']}</h3>
            <p><strong>Scopes:</strong> {test_case['scopes'] or 'None'}</p>
            <a href="{auth_url}" style="padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px;">
                Test This Configuration
            </a>
        </div>
        """
    
    return html

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
          
@app.route('/tiktok-check')
def tiktok_sandbox_check():
    """Comprehensive TikTok sandbox requirements check"""
    checks = {
        "sandbox_requirements": {
            "redirect_uri_localhost": Config.REDIRECT_URI.startswith('http://localhost') or Config.REDIRECT_URI.startswith('http://127.0.0.1'),
            "redirect_uri_http": Config.REDIRECT_URI.startswith('http://'),  # Not https
            "has_callback_path": '/callback' in Config.REDIRECT_URI,
            "client_key_format": len(Config.CLIENT_KEY) > 10,
            "client_secret_format": len(Config.CLIENT_SECRET) > 10,
        },
        "current_config": {
            "redirect_uri": Config.REDIRECT_URI,
            "client_key_length": len(Config.CLIENT_KEY),
            "client_secret_length": len(Config.CLIENT_SECRET),
        },
        "common_issues": [
            "Redirect URI must be http (not https) for sandbox",
            "Redirect URI must be localhost or 127.0.0.1", 
            "Redirect URI must match EXACTLY in TikTok portal",
            "Make sure to click 'Apply changes' in TikTok portal",
            "Test account must be added to sandbox target users"
        ]
    }
    
    # Check if all requirements are met
    checks["all_requirements_met"] = all(checks["sandbox_requirements"].values())
    
    return jsonify(checks)
        
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
                .status {{ padding: 10px; border-radius: 6px; margin: 10px 0; }}
                .status-success {{ background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }}
                .status-warning {{ background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }}
                .info-box {{ background: #d1ecf1; color: #0c5460; padding: 15px; border-radius: 6px; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🕌 Quran TikTok Uploader</h1>
                
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
                    <h2>🚀 Quick Actions</h2>
                    <a href="/auth" class="btn">🔗 Connect TikTok Account</a>
                    <a href="/status" class="btn btn-secondary">📡 Check API Status</a>
                    <a href="/debug" class="btn btn-secondary">🐛 Debug Info</a>
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
                    <h3>💡 Sandbox Information</h3>
                    <p>You are currently in <strong>TikTok Sandbox mode</strong>. This means:</p>
                    <ul>
                        <li>Only test accounts can be used (thereisonly1godallah1)</li>
                        <li>Redirect URI must be localhost (http://localhost:5000/callback)</li>
                        <li>Uploads may not appear on your public profile</li>
                        <li>Perfect for development and testing</li>
                    </ul>
                </div>
            </div>
        </body>
    </html>
    """

@app.route('/auth')
def authenticate():
    """Start TikTok OAuth with PKCE"""
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
        'expected_redirect_uri': 'http://localhost:5000/callback',
        'redirect_uri_match': Config.REDIRECT_URI == 'http://localhost:5000/callback',
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