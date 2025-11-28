# app.py (updated imports)
from flask import Flask, render_template, request, jsonify, redirect, session
import json
import os
import requests
from config import Config

app = Flask(__name__)
app.secret_key = 'your-secret-key-123-change-in-production'

# Import with fallback for video processor
try:
    from video_processor import VideoProcessor
    video_processor = VideoProcessor()
    VIDEO_PROCESSING_AVAILABLE = True
except ImportError as e:
    print(f"Video processing disabled: {e}")
    VIDEO_PROCESSING_AVAILABLE = False

# TikTok API (simplified)
class TikTokAPI:
    def __init__(self):
        self.client_key = Config.CLIENT_KEY
        self.client_secret = Config.CLIENT_SECRET
        self.redirect_uri = Config.REDIRECT_URI
    
    def get_auth_url(self):
        auth_url = (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={self.client_key}"
            "&scope=user.info.basic,video.upload,video.list"
            "&response_type=code"
            f"&redirect_uri={self.redirect_uri}"
        )
        return auth_url
    
    def exchange_code_for_token(self, auth_code):
        token_url = "https://open.tiktokapis.com/v2/oauth/token/"
        payload = {
            'client_key': self.client_key,
            'client_secret': self.client_secret,
            'code': auth_code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri
        }
        try:
            response = requests.post(token_url, data=payload)
            return response.json()
        except Exception as e:
            return {'error': str(e)}

tiktok_api = TikTokAPI()

@app.route('/')
def home():
    return """
    <html>
        <head><title>Quran TikTok Uploader</title></head>
        <body>
            <h1>🕌 Quran TikTok Uploader</h1>
            <p>Status: ✅ Basic server is running</p>
            <p>Video Processing: {}</p>
            <ul>
                <li><a href="/auth">1. Authenticate with TikTok</a></li>
                <li><a href="/status">2. Check API Status</a></li>
                <li><a href="/test-upload">3. Test Upload Form</a></li>
            </ul>
        </body>
    </html>
    """.format("✅ Available" if VIDEO_PROCESSING_AVAILABLE else "❌ Disabled")

@app.route('/auth')
def authenticate():
    auth_url = tiktok_api.get_auth_url()
    return redirect(auth_url)

@app.route('/callback')
def callback():
    auth_code = request.args.get('code')
    if auth_code:
        token_data = tiktok_api.exchange_code_for_token(auth_code)
        if 'access_token' in token_data:
            session['access_token'] = token_data['access_token']
            return f"""
            <h2>✅ Authentication Successful!</h2>
            <p>Access Token: {token_data['access_token'][:50]}...</p>
            <p><a href="/status">Check API Status</a></p>
            """
        else:
            return f"❌ Authentication failed: {token_data}"
    return "No authorization code received"

@app.route('/status')
def api_status():
    access_token = session.get('access_token')
    if access_token:
        return jsonify({
            'authenticated': True,
            'message': 'Ready to test TikTok API'
        })
    return jsonify({
        'authenticated': False,
        'message': 'Please authenticate first'
    })

@app.route('/test-upload')
def test_upload():
    return """
    <h2>Test Upload Form</h2>
    <p>Note: Full upload functionality will be added after basic setup works.</p>
    <p><a href="/auth">First, authenticate with TikTok</a></p>
    """

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)