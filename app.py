# app.py - Complete version with SDK authentication and fallbacks
from flask import Flask, render_template, request, jsonify, redirect, session
import json
import os
import requests
import hashlib
import base64
import secrets
from config import Config
# Add this at the top with other imports
from datetime import datetime
import time  # Alternative to datetime
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
    def upload_video(self, access_token, video_path, caption="", privacy_level="PUBLIC", category="EDUCATION", allow_duet=True, allow_stitch=True):
        """Upload video to TikTok"""
        try:
            # Try both possible endpoints
            upload_urls = [
                "https://open.tiktokapis.com/v2/video/publish/",
                "https://open.tiktokapis.com/v2/video/upload/",
                "https://business-api.tiktok.com/open_api/v1.3/video/upload/"
            ]
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            for upload_url in upload_urls:
                try:
                    print(f"📤 Trying upload endpoint: {upload_url}")
                    
                    with open(video_path, 'rb') as video_file:
                        files = {
                            'video': (os.path.basename(video_path), video_file, 'video/mp4')
                        }
                        
                        data = {
                            'caption': caption,
                            'privacy_level': privacy_level,
                            'category': category,
                            'allow_duet': 'true' if allow_duet else 'false',
                            'allow_stitch': 'true' if allow_stitch else 'false'
                        }
                        
                        print(f"📤 Uploading to {upload_url}...")
                        response = requests.post(upload_url, headers=headers, files=files, data=data, timeout=30)
                        
                        print(f"📥 Response status: {response.status_code}")
                        print(f"📥 Response headers: {dict(response.headers)}")
                        print(f"📥 Response text (first 500 chars): {response.text[:500]}")
                        
                        # Try to parse as JSON
                        try:
                            result = response.json()
                            print(f"✅ Parsed JSON response: {result}")
                            return result
                        except json.JSONDecodeError:
                            # Not JSON, return raw response
                            return {
                                'status_code': response.status_code,
                                'text': response.text,
                                'headers': dict(response.headers),
                                'error': 'Response not in JSON format'
                            }
                            
                except Exception as e:
                    print(f"❌ Failed with endpoint {upload_url}: {e}")
                    continue
            
            return {'error': 'All upload endpoints failed'}
                    
        except Exception as e:
            print(f"❌ Upload error: {e}")
            return {'error': str(e)}
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
    
    # Add upload button to the authenticated section
    upload_button = ''
    if authenticated:
        # In your home route, replace the test upload link with:
        upload_button = '''
        <div class="card">
            <h2>🎬 Ready to Upload</h2>
            <p>Your TikTok account is connected and ready for video uploads.</p>
            <a href="/upload-video" class="btn" style="background: #28a745;">🎬 Upload Video Now</a>
            <a href="/status" class="btn btn-secondary">📡 Check API Status</a>
        </div>
        '''
    
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
                    <p><strong>Ready for:</strong> {'🎬 Video Uploads' if authenticated else '🔐 Authentication'}</p>
                </div>

                {upload_button if authenticated else '''
                <div class="card">
                    <h2>🚀 Get Started</h2>
                    <a href="/auth" class="btn">🔗 Connect TikTok Account</a>
                    <a href="/status" class="btn btn-secondary">📡 Check API Status</a>
                </div>
                '''}

                
                    <div class="card">
                        <h2>📋 Quick Actions</h2>
                        <a href="/upload-video" class="btn {'btn-secondary' if not authenticated else ''}">🎬 Upload Video</a>
                        <a href="/status" class="btn btn-secondary">📡 API Status</a>
                        <a href="/debug" class="btn btn-secondary">🐛 Debug</a>
                    </div>
            </div>
        </body>
    </html>
    """

@app.route('/auth')
def authenticate():
    """Original OAuth with CSP fix"""
    try:
        print("🔄 Starting OAuth flow...")
        auth_url = tiktok_api.get_auth_url()
        print(f"🔗 Redirecting to: {auth_url[:200]}...")
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting to TikTok...</title>
            <meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;">
            <meta name="referrer" content="no-referrer">
            <script>
                // Open in popup window to isolate from parent page CSP
                function openTikTokAuth() {{
                    const width = 600;
                    const height = 700;
                    const left = window.screen.width / 2 - width / 2;
                    const top = window.screen.height / 2 - height / 2;
                    
                    const popup = window.open(
                        "{auth_url}",
                        "tiktok_auth",
                        `width=${{width}},height=${{height}},left=${{left}},top=${{top}},resizable=yes,scrollbars=yes,status=yes`
                    );
                    
                    // Check for completion every second
                    const checkPopup = setInterval(() => {{
                        if (popup.closed) {{
                            clearInterval(checkPopup);
                            window.location.href = "/auth-check";
                        }}
                    }}, 1000);
                }}
                
                document.addEventListener('DOMContentLoaded', openTikTokAuth);
            </script>
        </head>
        <body style="font-family: Arial; margin: 40px; text-align: center;">
            <h2>🔄 Opening TikTok Authentication...</h2>
            <p>If popup is blocked, <a href="{auth_url}" target="_blank">click here</a></p>
            <div id="status">Opening authentication window...</div>
        </body>
        </html>
        """
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

@app.route('/auth-check')
def auth_check():
    """Check if authentication was completed"""
    access_token = session.get('access_token')
    
    if access_token:
        return """
        <html>
        <head>
            <title>✅ Authentication Complete</title>
            <style>
                body { font-family: Arial; margin: 40px; text-align: center; }
                .success { background: #d4edda; color: #155724; padding: 20px; border-radius: 8px; }
            </style>
        </head>
        <body>
            <div class="success">
                <h1>✅ Authentication Successful!</h1>
                <p>Your TikTok account has been connected.</p>
                <p><a href="/">Go to Dashboard</a></p>
            </div>
        </body>
        </html>
        """
    else:
        return """
        <html>
        <head>
            <title>❌ Authentication Failed</title>
            <style>
                body { font-family: Arial; margin: 40px; text-align: center; }
                .error { background: #f8d7da; color: #721c24; padding: 20px; border-radius: 8px; }
            </style>
        </head>
        <body>
            <div class="error">
                <h1>❌ Authentication Failed</h1>
                <p>The authentication process did not complete successfully.</p>
                <p><a href="/auth">Try Again</a> | <a href="/">Back to Home</a></p>
            </div>
        </body>
        </html>
        """
# Add this to your app.py to verify production setup

@app.route('/api/upload', methods=['POST'])
def api_upload_video():
    """API endpoint for video upload"""
    try:
        access_token = session.get('access_token')
        if not access_token:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        # Get form data
        video_file = request.files.get('video')
        caption = request.form.get('caption', '')
        privacy_level = request.form.get('privacy_level', 'PUBLIC')
        category = request.form.get('category', 'EDUCATION')
        allow_duet = request.form.get('allow_duet', 'true') == 'true'
        allow_stitch = request.form.get('allow_stitch', 'true') == 'true'
        
        if not video_file:
            return jsonify({'success': False, 'error': 'No video file provided'})
        
        print(f"🎬 Starting upload: {video_file.filename}")
        print(f"📝 Caption: {caption}")
        print(f"🔐 Privacy: {privacy_level}")
        
        # Save temporary file
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.mp4') as temp_file:
            video_file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            # Upload to TikTok
            upload_result = tiktok_api.upload_video(
                access_token=access_token,
                video_path=temp_path,
                caption=caption,
                privacy_level=privacy_level,
                category=category,
                allow_duet=allow_duet,
                allow_stitch=allow_stitch
            )
            
            print(f"📤 Upload result type: {type(upload_result)}")
            print(f"📤 Upload result: {upload_result}")
            
            # Handle different response formats
            if isinstance(upload_result, dict):
                if 'data' in upload_result and 'publish_id' in upload_result['data']:
                    return jsonify({
                        'success': True,
                        'video_id': upload_result['data'].get('publish_id'),
                        'status': 'uploaded',
                        'message': 'Video successfully uploaded to TikTok!',
                        'details': upload_result
                    })
                elif 'error' in upload_result:
                    return jsonify({
                        'success': False,
                        'error': upload_result.get('error', 'Upload failed'),
                        'details': upload_result
                    })
                else:
                    return jsonify({
                        'success': True,
                        'message': 'Upload completed (check details)',
                        'details': upload_result
                    })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Unexpected response type: {type(upload_result)}',
                    'details': str(upload_result)[:500]
                })
                
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except:
                pass
            
    except Exception as e:
        print(f"❌ Upload error: {e}")
        import traceback
        traceback.print_exc()
        
        return jsonify({
            'success': False,
            'error': f'Upload failed: {str(e)}',
            'traceback': traceback.format_exc()
        })
        
# Add this at the top of your upload_video_page function (after authentication check):
@app.route('/upload-video')
def upload_video_page():
    """Video upload interface"""
    access_token = session.get('access_token')
    if not access_token:
        return redirect('/')
    
    # Check if we're in sandbox mode
    sandbox_warning = ""
    if not IS_RENDER:
        sandbox_warning = """
        <div style="background: #fff3cd; color: #856404; padding: 15px; border-radius: 8px; margin: 20px 0;">
            <h3>⚠️ Sandbox Mode</h3>
            <p>You are currently in <strong>TikTok Sandbox mode</strong>. In sandbox:</p>
            <ul>
                <li>Video uploads might be simulated</li>
                <li>Uploads won't appear on your public profile</li>
                <li>Perfect for testing without affecting your account</li>
                <li>Use small test videos (under 50MB)</li>
            </ul>
            <p><strong>Test Account:</strong> thereisonly1godallah1</p>
        </div>
        """
    
    # JavaScript code as a separate variable
    javascript_code = """
    <script>
        // File size and type validation
        document.getElementById('video').addEventListener('change', function(e) {
            const file = e.target.files[0];
            const resultDiv = document.getElementById('result');
            
            if (file) {
                const fileSizeMB = (file.size / (1024 * 1024)).toFixed(2);
                const maxSizeMB = 500;
                
                // Check file type
                const allowedTypes = ['video/mp4', 'video/quicktime', 'video/x-msvideo'];
                if (!allowedTypes.includes(file.type)) {
                    resultDiv.innerHTML = `
                        <div class="result-box error" style="display: block;">
                            <h3>❌ Invalid File Type</h3>
                            <p>Please select a video file (MP4, MOV, or AVI format).</p>
                            <p>Selected file type: ${file.type || 'Unknown'}</p>
                        </div>
                    `;
                    this.value = ''; // Clear the file input
                    return;
                }
                
                // Check file size
                if (file.size > maxSizeMB * 1024 * 1024) {
                    resultDiv.innerHTML = `
                        <div class="result-box error" style="display: block;">
                            <h3>❌ File Too Large</h3>
                            <p>Maximum file size is ${maxSizeMB}MB.</p>
                            <p>Your file: ${fileSizeMB}MB</p>
                        </div>
                    `;
                    this.value = '';
                    return;
                }
                
                // Show file info
                resultDiv.innerHTML = `
                    <div class="result-box success" style="display: block;">
                        <h3>✅ File Ready</h3>
                        <p><strong>File:</strong> ${file.name}</p>
                        <p><strong>Size:</strong> ${fileSizeMB} MB</p>
                        <p><strong>Type:</strong> ${file.type.split('/')[1].toUpperCase()}</p>
                    </div>
                `;
            }
        });
        
        // Form submission
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData();
            const videoFile = document.getElementById('video').files[0];
            const caption = document.getElementById('caption').value;
            const privacy = document.getElementById('privacy').value;
            const category = document.getElementById('category').value;
            const allowDuet = document.getElementById('allow_duet').value;
            const allowStitch = document.getElementById('allow_stitch').value;
            
            // UI elements
            const progressBar = document.getElementById('progressBar');
            const progressFill = document.getElementById('progressFill');
            const resultDiv = document.getElementById('result');
            const uploadButton = document.getElementById('uploadButton');
            
            if (!videoFile) {
                resultDiv.innerHTML = `
                    <div class="result-box error" style="display: block;">
                        <h3>❌ No File Selected</h3>
                        <p>Please select a video file to upload.</p>
                    </div>
                `;
                return;
            }
            
            // Disable button and show progress
            uploadButton.disabled = true;
            uploadButton.innerHTML = '🔄 Uploading...';
            progressBar.style.display = 'block';
            resultDiv.innerHTML = `
                <div class="result-box" style="display: block; background: #fff3cd; color: #856404;">
                    <h3>🔄 Starting Upload...</h3>
                    <p>Preparing to upload: ${videoFile.name}</p>
                    <p>Size: ${(videoFile.size / (1024 * 1024)).toFixed(2)} MB</p>
                </div>
            `;
            
            // Update progress bar
            let progress = 0;
            const progressInterval = setInterval(() => {
                if (progress < 90) {
                    progress += 10;
                    progressFill.style.width = progress + '%';
                    progressFill.textContent = progress + '%';
                }
            }, 500);
            
            // Prepare form data
            formData.append('video', videoFile);
            formData.append('caption', caption);
            formData.append('privacy_level', privacy);
            formData.append('category', category);
            formData.append('allow_duet', allowDuet);
            formData.append('allow_stitch', allowStitch);
            
            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                
                clearInterval(progressInterval);
                progressFill.style.width = '100%';
                progressFill.textContent = '100%';
                
                const data = await response.json();
                
                if (data.success) {
                    resultDiv.innerHTML = `
                        <div class="result-box success" style="display: block;">
                            <h3>✅ Upload Successful!</h3>
                            <p><strong>🎉 Video uploaded to TikTok!</strong></p>
                            ${data.video_id ? `<p><strong>Video ID:</strong> ${data.video_id}</p>` : ''}
                            <p><strong>Status:</strong> ${data.status || 'Uploaded'}</p>
                            <p><strong>Privacy:</strong> ${privacy}</p>
                            <p>${data.message || 'Your video has been successfully uploaded.'}</p>
                            <button onclick="location.reload()" style="margin-top: 15px; padding: 10px 20px; background: #28a745; color: white; border: none; border-radius: 5px; cursor: pointer;">
                                📤 Upload Another Video
                            </button>
                        </div>
                    `;
                } else {
                    resultDiv.innerHTML = `
                        <div class="result-box error" style="display: block;">
                            <h3>❌ Upload Failed</h3>
                            <p><strong>Error:</strong> ${data.error || 'Unknown error'}</p>
                            ${data.details ? `<p><strong>Details:</strong> ${JSON.stringify(data.details)}</p>` : ''}
                            <button onclick="location.reload()" style="margin-top: 15px; padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer;">
                                🔄 Try Again
                            </button>
                        </div>
                    `;
                }
            } catch (error) {
                clearInterval(progressInterval);
                resultDiv.innerHTML = `
                    <div class="result-box error" style="display: block;">
                        <h3>❌ Upload Error</h3>
                        <p><strong>Network Error:</strong> ${error.message}</p>
                        <p>Please check your connection and try again.</p>
                        <button onclick="location.reload()" style="margin-top: 15px; padding: 10px 20px; background: #dc3545; color: white; border: none; border-radius: 5px; cursor: pointer;">
                            🔄 Try Again
                        </button>
                    </div>
                `;
            } finally {
                uploadButton.disabled = false;
                uploadButton.innerHTML = '🚀 Upload to TikTok';
            }
        });
    </script>
    """
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Upload Video to TikTok</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 700px; margin: 0 auto; }}
            .card {{ background: white; padding: 30px; border-radius: 15px; margin: 25px 0; box-shadow: 0 2px 15px rgba(0,0,0,0.1); }}
            .form-group {{ margin: 20px 0; }}
            label {{ display: block; margin-bottom: 8px; font-weight: bold; color: #333; }}
            input[type="file"], textarea, select {{ 
                width: 100%; 
                padding: 12px; 
                border: 2px solid #ddd; 
                border-radius: 8px; 
                font-size: 16px;
                box-sizing: border-box;
            }}
            input[type="file"]:focus, textarea:focus, select:focus {{
                border-color: #FF0050;
                outline: none;
                box-shadow: 0 0 0 3px rgba(255, 0, 80, 0.1);
            }}
            textarea {{ min-height: 100px; resize: vertical; }}
            button {{ 
                padding: 15px 40px; 
                background: linear-gradient(135deg, #FF0050, #FF3366); 
                color: white; 
                border: none; 
                border-radius: 10px; 
                font-size: 18px; 
                font-weight: bold;
                cursor: pointer; 
                width: 100%;
                transition: transform 0.2s, box-shadow 0.2s;
            }}
            button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(255, 0, 80, 0.3);
            }}
            .progress {{ 
                display: none; 
                background: #e9ecef; 
                border-radius: 10px; 
                margin: 20px 0; 
                overflow: hidden;
                height: 25px;
            }}
            .progress-bar {{ 
                background: linear-gradient(90deg, #28a745, #20c997); 
                height: 100%; 
                width: 0%; 
                transition: width 0.5s;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: bold;
            }}
            .result-box {{ 
                padding: 20px; 
                border-radius: 10px; 
                margin-top: 20px;
                display: none;
            }}
            .success {{ background: #d4edda; color: #155724; border: 2px solid #c3e6cb; }}
            .error {{ background: #f8d7da; color: #721c24; border: 2px solid #f5c6cb; }}
            .info-box {{ background: #d1ecf1; color: #0c5460; padding: 15px; border-radius: 8px; margin: 15px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1 style="color: #FF0050; text-align: center;">🎬 Upload Video to TikTok</h1>
            <p style="text-align: center; color: #666;">Share your Quran videos directly from your server</p>
            
            {sandbox_warning}
            
            <div class="card">
                <h2 style="color: #333; margin-top: 0;">📤 Video Upload Form</h2>
                
                <form id="uploadForm" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="video">🎥 Select Video File:</label>
                        <input type="file" id="video" name="video" accept="video/mp4,video/quicktime,video/x-msvideo" required>
                        <div class="info-box">
                            <strong>📋 Requirements:</strong>
                            <ul style="margin: 5px 0; padding-left: 20px;">
                                <li>Formats: MP4, MOV, AVI</li>
                                <li>Maximum size: 500MB</li>
                                <li>Recommended: Short videos (3-60 seconds)</li>
                                <li>Vertical format (9:16) works best</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="caption">📝 Caption:</label>
                        <textarea id="caption" name="caption" rows="3" placeholder="Enter your video caption with hashtags... 
    Example: Beautiful Quran recitation #Quran #Islam #Islamic #Allah #Muslim"></textarea>
                        <small style="color: #666;">Tip: Use relevant hashtags like #Quran, #Islam, #Islamic, #Muslim</small>
                    </div>
                    
                    <div class="form-group">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                            <div>
                                <label for="privacy">🔒 Privacy Setting:</label>
                                <select id="privacy" name="privacy">
                                    <option value="PUBLIC">🌎 Public</option>
                                    <option value="FRIENDS">👥 Friends Only</option>
                                    <option value="PRIVATE">🔐 Private</option>
                                </select>
                            </div>
                            <div>
                                <label for="category">📁 Category:</label>
                                <select id="category" name="category">
                                    <option value="EDUCATION">📚 Education</option>
                                    <option value="RELIGION">🕌 Religion</option>
                                    <option value="MUSIC">🎵 Music</option>
                                    <option value="OTHER">📦 Other</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                            <div>
                                <label for="allow_duet">🎭 Allow Duet:</label>
                                <select id="allow_duet" name="allow_duet">
                                    <option value="true">✅ Yes</option>
                                    <option value="false">❌ No</option>
                                </select>
                            </div>
                            <div>
                                <label for="allow_stitch">🎬 Allow Stitch:</label>
                                <select id="allow_stitch" name="allow_stitch">
                                    <option value="true">✅ Yes</option>
                                    <option value="false">❌ No</option>
                                </select>
                            </div>
                        </div>
                    </div>
                    
                    <button type="submit" id="uploadButton">
                        🚀 Upload to TikTok
                    </button>
                </form>
                
                <div class="progress" id="progressBar">
                    <div class="progress-bar" id="progressFill">0%</div>
                </div>
                
                <div id="result" class="result-box"></div>
            </div>
            
            <div style="text-align: center; margin-top: 30px;">
                <a href="/" style="color: #FF0050; text-decoration: none; font-weight: bold;">← Back to Dashboard</a>
                <span style="margin: 0 10px;">•</span>
                <a href="/status" style="color: #666; text-decoration: none;">📊 Check Status</a>
            </div>
        </div>
        
        {javascript_code}
    </body>
    </html>
    """
@app.route('/debug-upload')
def debug_upload():
    """Debug video upload capabilities"""
    access_token = session.get('access_token')
    
    if not access_token:
        return jsonify({'error': 'Not authenticated'})
    
    # Test if we can access video-related endpoints
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    tests = {}
    
    # Test 1: Check video list endpoint (usually available in sandbox)
    try:
        list_url = "https://open.tiktokapis.com/v2/video/list/"
        response = requests.get(list_url, headers=headers)
        tests['video_list'] = {
            'status': response.status_code,
            'json': response.json() if response.status_code == 200 else response.text[:200]
        }
    except Exception as e:
        tests['video_list'] = {'error': str(e)}
    
    # Test 2: Check upload endpoint availability
    try:
        upload_info_url = "https://open.tiktokapis.com/v2/video/upload/info/"
        response = requests.get(upload_info_url, headers=headers)
        tests['upload_info'] = {
            'status': response.status_code,
            'json': response.json() if response.status_code == 200 else response.text[:200]
        }
    except Exception as e:
        tests['upload_info'] = {'error': str(e)}
    
    # Test 3: Check user permissions
    try:
        user_url = "https://open.tiktokapis.com/v2/user/info/"
        response = requests.get(user_url, headers=headers)
        user_data = response.json() if response.status_code == 200 else {}
        tests['user_info'] = {
            'status': response.status_code,
            'scopes': user_data.get('data', {}).get('user', {}).get('scopes', [])
        }
    except Exception as e:
        tests['user_info'] = {'error': str(e)}
    
    return jsonify({
        'authenticated': True,
        'access_token_short': access_token[:50] + '...',
        'tests': tests,
        'sandbox_info': 'Video upload might be limited in sandbox mode'
    })
@app.route('/sdk-auth')
def sdk_auth():
    """Use TikTok's JavaScript SDK for authentication"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>TikTok SDK Authentication</title>
        <!-- Try different SDK URLs -->
        <script src="https://sf16-website-login.neutral.ttwstatic.com/obj/tiktok_web_login_static/sdk.js"></script>
        <!-- Fallback SDK URL -->
        <script src="https://js16.tiktokcdn.com/byte/webview-ttnet/sdk.js"></script>
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
            // Wait for SDK to load
            function waitForSDK(callback, maxAttempts = 10) {
                let attempts = 0;
                const checkSDK = setInterval(() => {
                    attempts++;
                    if (typeof window.tt !== 'undefined') {
                        clearInterval(checkSDK);
                        callback(true);
                    } else if (attempts >= maxAttempts) {
                        clearInterval(checkSDK);
                        callback(false);
                    }
                }, 500);
            }

            // Initialize TikTok SDK
            function authenticateWithSDK() {
                const status = document.getElementById('status');
                status.style.display = 'block';
                status.innerHTML = '<p>🔄 Checking TikTok SDK...</p>';
                
                waitForSDK(function(sdkLoaded) {
                    if (!sdkLoaded) {
                        status.innerHTML = '<p style="color: red;">❌ TikTok SDK failed to load. Try alternative methods below.</p>';
                        return;
                    }
                    
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
                });
            }
            
            // Check if SDK loaded on page load
            document.addEventListener('DOMContentLoaded', function() {
                const status = document.getElementById('status');
                waitForSDK(function(sdkLoaded) {
                    if (sdkLoaded) {
                        status.innerHTML = '<p style="color: green;">✅ TikTok SDK Loaded Successfully</p>';
                    } else {
                        status.innerHTML = '<p style="color: orange;">⚠️ TikTok SDK may not load. Try alternative methods.</p>';
                    }
                });
            });
        </script>
        
        <div style="margin-top: 30px; padding: 15px; background: #f8f9fa; border-radius: 5px;">
            <h3>🎯 If SDK Fails, Try These Alternatives:</h3>
            <ul>
                <li><a href="/mobile-simulated-auth">📱 Mobile-Simulated Auth</a> (Most reliable)</li>
                <li><a href="/direct-auth-test">🔗 Direct Auth Test</a></li>
                <li><a href="/manual-token-setup">🔧 Manual Token Setup</a></li>
            </ul>
        </div>
    </body>
    </html>
    """
@app.route('/direct-auth-test')
def direct_auth_test():
    """Direct authentication test with multiple options"""
    auth_urls = {
        "basic": (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={Config.CLIENT_KEY}"
            "&scope=user.info.basic"
            "&response_type=code"
            f"&redirect_uri={Config.REDIRECT_URI}"
        ),
        "no_scope": (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={Config.CLIENT_KEY}"
            "&response_type=code"
            f"&redirect_uri={Config.REDIRECT_URI}"
        ),
        "minimal": (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={Config.CLIENT_KEY}"
            "&response_type=code"
            f"&redirect_uri={Config.REDIRECT_URI}"
            "&scope=user.info.basic"
        )
    }
    
    html = """
    <html>
    <head>
        <title>Direct Auth Test</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            .test-case { border: 1px solid #ddd; padding: 20px; margin: 15px 0; border-radius: 8px; }
            .btn { padding: 12px 24px; background: #FF0050; color: white; text-decoration: none; border-radius: 6px; display: inline-block; margin: 5px; }
        </style>
    </head>
    <body>
        <h1>🔗 Direct Authentication Tests</h1>
        <p>Try these different authentication configurations:</p>
    """
    
    for name, url in auth_urls.items():
        html += f"""
        <div class="test-case">
            <h3>Test: {name.replace('_', ' ').title()}</h3>
            <a href="{url}" class="btn" target="_blank">Test This Config</a>
            <details style="margin-top: 10px;">
                <summary>Show URL</summary>
                <code style="word-break: break-all; font-size: 12px;">{url}</code>
            </details>
        </div>
        """
    
    html += """
        <div style="background: #e7f3ff; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>💡 Pro Tip:</h3>
            <p>Open links in <strong>Incognito Mode</strong> to avoid extension conflicts.</p>
            <p>Right-click → "Open in new incognito window"</p>
        </div>
    </body>
    </html>
    """
    
    return html
@app.route('/test-minimal-upload')
def test_minimal_upload():
    """Test minimal video upload with a small test video"""
    access_token = session.get('access_token')
    
    if not access_token:
        return redirect('/')
    
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Minimal Upload</title>
        <style>
            body { font-family: Arial; margin: 40px; }
            .btn { padding: 15px 30px; background: #28a745; color: white; text-decoration: none; border-radius: 8px; }
        </style>
    </head>
    <body>
        <h1>🧪 Test Minimal Upload</h1>
        <p>Testing with a very small video file...</p>
        
        <button onclick="testUpload()" class="btn">🧪 Test Upload</button>
        
        <div id="result" style="margin-top: 20px;"></div>
        
        <script>
            async function testUpload() {
                const resultDiv = document.getElementById('result');
                resultDiv.innerHTML = '<p>🔄 Testing upload...</p>';
                
                try {
                    // Create a minimal test video (1 second black video)
                    const canvas = document.createElement('canvas');
                    canvas.width = 640;
                    canvas.height = 360;
                    const ctx = canvas.getContext('2d');
                    ctx.fillStyle = 'black';
                    ctx.fillRect(0, 0, 640, 360);
                    
                    // Convert to blob
                    const blob = await new Promise(resolve => canvas.toBlob(resolve, 'video/webm'));
                    
                    const formData = new FormData();
                    formData.append('video', blob, 'test.webm');
                    formData.append('caption', 'Test video from Quran TikTok Uploader');
                    formData.append('privacy_level', 'PRIVATE');
                    
                    const response = await fetch('/api/upload-test', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await response.json();
                    
                    resultDiv.innerHTML = `
                        <div style="background: #d4edda; padding: 20px; border-radius: 8px;">
                            <h3>✅ Test Complete</h3>
                            <pre>${JSON.stringify(data, null, 2)}</pre>
                        </div>
                    `;
                    
                } catch (error) {
                    resultDiv.innerHTML = `
                        <div style="background: #f8d7da; padding: 20px; border-radius: 8px;">
                            <h3>❌ Test Failed</h3>
                            <p>Error: ${error.message}</p>
                        </div>
                    `;
                }
            }
        </script>
    </body>
    </html>
    """

@app.route('/api/upload-test', methods=['POST'])
def api_upload_test():
    """Test upload endpoint with minimal data"""
    try:
        access_token = session.get('access_token')
        if not access_token:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        # Just test if the endpoint responds
        headers = {
            'Authorization': f'Bearer {access_token}',
        }
        
        test_url = "https://open.tiktokapis.com/v2/video/publish/"
        
        # Send a minimal request
        response = requests.post(test_url, headers=headers, data={'test': 'true'})
        
        return jsonify({
            'success': True,
            'test': 'completed',
            'status_code': response.status_code,
            'response_headers': dict(response.headers),
            'response_text_preview': response.text[:200] if response.text else 'Empty response'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'type': type(e).__name__
        })
@app.route('/minimal-auth')
def minimal_auth():
    """Minimal authentication without PKCE - just basic parameters"""
    auth_url = (
        f"https://www.tiktok.com/v2/auth/authorize/"
        f"?client_key={Config.CLIENT_KEY}"
        "&response_type=code"
        f"&redirect_uri={Config.REDIRECT_URI}"
        # No scope, no PKCE - absolute minimum
    )
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Minimal TikTok Auth</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body style="font-family: Arial; margin: 40px;">
        <h1>🧪 Minimal Authentication Test</h1>
        <p>Testing with absolute minimum parameters (no PKCE, no scopes)</p>
        
        <div style="background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3>🔧 Parameters Used:</h3>
            <ul>
                <li><strong>client_key:</strong> {Config.CLIENT_KEY[:10]}...</li>
                <li><strong>response_type:</strong> code</li>
                <li><strong>redirect_uri:</strong> {Config.REDIRECT_URI}</li>
                <li><strong>scope:</strong> None</li>
                <li><strong>PKCE:</strong> Disabled</li>
            </ul>
        </div>
        
        <a href="{auth_url}" style="padding: 15px 30px; background: #28a745; color: white; text-decoration: none; border-radius: 8px; font-size: 18px; display: inline-block;">
            🚀 Test Minimal Authentication
        </a>
        
        <div style="margin-top: 30px;">
            <h3>Other Test Options:</h3>
            <a href="/test-all-methods" style="color: #007bff;">View All Test Methods</a>
        </div>
    </body>
    </html>
    """
@app.route('/test-all-methods')
def test_all_methods():
    """Test all possible authentication configurations"""
    
    test_cases = [
        {
            "name": "Minimal (No PKCE, No Scope)",
            "url": f"https://www.tiktok.com/v2/auth/authorize/?client_key={Config.CLIENT_KEY}&response_type=code&redirect_uri={Config.REDIRECT_URI}",
            "description": "Absolute minimum parameters"
        },
        {
            "name": "Basic Scope Only", 
            "url": f"https://www.tiktok.com/v2/auth/authorize/?client_key={Config.CLIENT_KEY}&response_type=code&redirect_uri={Config.REDIRECT_URI}&scope=user.info.basic",
            "description": "Basic scope without PKCE"
        },
        {
            "name": "With Simple PKCE",
            "url": f"https://www.tiktok.com/v2/auth/authorize/?client_key={Config.CLIENT_KEY}&response_type=code&redirect_uri={Config.REDIRECT_URI}&scope=user.info.basic&code_challenge=simple_test&code_challenge_method=plain",
            "description": "Simple PKCE without complex encoding"
        },
        {
            "name": "Different Redirect (No Port)",
            "url": f"https://www.tiktok.com/v2/auth/authorize/?client_key={Config.CLIENT_KEY}&response_type=code&redirect_uri=http://127.0.0.1/callback&scope=user.info.basic",
            "description": "Redirect without port 5000"
        },
        {
            "name": "Localhost Redirect",
            "url": f"https://www.tiktok.com/v2/auth/authorize/?client_key={Config.CLIENT_KEY}&response_type=code&redirect_uri=http://localhost:5000/callback&scope=user.info.basic", 
            "description": "Using localhost instead of 127.0.0.1"
        }
    ]
    
    html = f"""
    <html>
    <head>
        <title>Comprehensive TikTok Auth Tests</title>
        <style>
            body {{ font-family: Arial; margin: 40px; }}
            .test-case {{ border: 1px solid #ddd; padding: 20px; margin: 15px 0; border-radius: 8px; }}
            .btn {{ padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; display: inline-block; margin: 5px; }}
            .btn-success {{ background: #28a745; }}
            .btn-warning {{ background: #ffc107; color: black; }}
            .status {{ padding: 10px; border-radius: 5px; margin: 10px 0; }}
            .status-info {{ background: #d1ecf1; color: #0c5460; }}
        </style>
    </head>
    <body>
        <h1>🧪 Comprehensive Authentication Tests</h1>
        
        <div class="status status-info">
            <h3>🔍 Debug Information</h3>
            <p><strong>Current Config:</strong> {Config.REDIRECT_URI}</p>
            <p><strong>Last Error:</strong> code_challenge validation</p>
            <p><strong>Strategy:</strong> Testing different parameter combinations to find what works</p>
        </div>
    """
    
    for i, test in enumerate(test_cases):
        html += f"""
        <div class="test-case">
            <h3>Test #{i+1}: {test['name']}</h3>
            <p>{test['description']}</p>
            <a href="{test['url']}" class="btn {'btn-success' if i == 0 else 'btn-warning'}" target="_blank">
                🚀 Test This Configuration
            </a>
            <details style="margin-top: 10px;">
                <summary>Show URL Details</summary>
                <code style="word-break: break-all; font-size: 11px; display: block; background: #f8f9fa; padding: 10px; margin-top: 5px;">
                    {test['url']}
                </code>
            </details>
        </div>
        """
    
    html += """
        <div style="background: #fff3cd; padding: 20px; border-radius: 8px; margin-top: 20px;">
            <h3>💡 Testing Instructions:</h3>
            <ol>
                <li>Start with <strong>Test #1 (Minimal)</strong> - it has the best chance of working</li>
                <li>If it fails, note the exact error message</li>
                <li>Try the other tests one by one</li>
                <li>Use <strong>Incognito Mode</strong> for each test</li>
                <li>Report which test (if any) works</li>
            </ol>
        </div>
    </body>
    </html>
    """
    
    return html
@app.route('/exchange-simple-token', methods=['POST'])
def exchange_simple_token():
    """Exchange auth code for token without PKCE verification"""
    try:
        data = request.json
        auth_code = data.get('authCode')
        
        if not auth_code:
            return jsonify({'error': 'No auth code provided'})
        
        # Exchange without PKCE (for testing)
        token_url = "https://open.tiktokapis.com/v2/oauth/token/"
        payload = {
            'client_key': Config.CLIENT_KEY,
            'client_secret': Config.CLIENT_SECRET,
            'code': auth_code,
            'grant_type': 'authorization_code',
            'redirect_uri': Config.REDIRECT_URI
            # No code_verifier for non-PKCE flow
        }
        
        response = requests.post(token_url, data=payload)
        token_data = response.json()
        
        print(f"🔧 Token exchange response: {token_data}")
        
        if 'access_token' in token_data:
            session['access_token'] = token_data['access_token']
            return jsonify({
                'success': True,
                'access_token': token_data['access_token'],
                'message': 'Authentication successful!'
            })
        else:
            return jsonify({
                'success': False,
                'error': token_data,
                'message': 'Token exchange failed'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)})    
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
@app.route('/mobile-simulated-auth')
def mobile_simulated_auth():
    """Mobile-simulated authentication that bypasses desktop JS issues"""
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
        <title>Mobile-Simulated TikTok Auth</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
        <script>
            // Force mobile environment
            function forceMobileEnvironment() {{
                // Override user agent
                Object.defineProperty(navigator, 'userAgent', {{
                    get: function() {{
                        return 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1';
                    }}
                }});
                
                // Force mobile viewport
                const viewport = document.querySelector('meta[name="viewport"]');
                viewport.setAttribute('content', 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no');
                
                // Add mobile CSS
                const style = document.createElement('style');
                style.textContent = `
                    body {{
                        -webkit-text-size-adjust: 100%;
                        touch-action: manipulation;
                    }}
                `;
                document.head.appendChild(style);
            }}
            
            // Initialize mobile environment and redirect
            document.addEventListener('DOMContentLoaded', function() {{
                forceMobileEnvironment();
                
                // Show status
                const status = document.getElementById('status');
                status.innerHTML = '<p>📱 Simulating mobile environment...</p>';
                
                // Wait a moment then redirect
                setTimeout(function() {{
                    status.innerHTML = '<p>🔄 Redirecting to TikTok mobile auth...</p>';
                    window.location.href = "{auth_url}";
                }}, 1000);
            }});
        </script>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 20px;
                background: #f5f5f5;
            }}
            .mobile-container {{
                max-width: 400px;
                margin: 0 auto;
                background: white;
                border-radius: 12px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
        </style>
    </head>
    <body>
        <div class="mobile-container">
            <h2 style="text-align: center; color: #FF0050;">📱 Mobile Authentication</h2>
            <p style="text-align: center;">Simulating mobile environment to avoid desktop JS issues...</p>
            <div id="status" style="text-align: center; padding: 20px;"></div>
            <p style="text-align: center; font-size: 14px; color: #666;">
                If not redirected automatically, <a href="{auth_url}">click here</a>.
            </p>
        </div>
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
@app.route('/callback')
def callback():
    """Handle TikTok OAuth callback"""
    print("✅ Callback route hit!")
    print(f"📥 Request URL: {request.url}")
    print(f"📥 Query params: {dict(request.args)}")
    
    # Get authorization code from query parameters
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        return f"""
        <html>
        <body style="font-family: Arial; margin: 40px;">
            <h1>❌ Authentication Failed</h1>
            <div style="background: #f8d7da; padding: 20px; border-radius: 8px;">
                <p><strong>Error:</strong> {error}</p>
                <p><strong>Description:</strong> {error_description}</p>
            </div>
            <p><a href="/">← Back to Home</a></p>
        </body>
        </html>
        """
    
    if not code:
        return "❌ Error: No authorization code received", 400
    
    print(f"✅ Received authorization code: {code[:50]}...")
    
    try:
        # Store code in session for debugging
        session['auth_code'] = code
        
        # Exchange code for access token (simplified for testing)
        token_url = "https://open.tiktokapis.com/v2/oauth/token/"
        
        payload = {
            'client_key': Config.CLIENT_KEY,
            'client_secret': Config.CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': Config.REDIRECT_URI
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cache-Control': 'no-cache'
        }
        
        print(f"📤 Making token request...")
        response = requests.post(token_url, data=payload, headers=headers)
        
        print(f"📥 Token response status: {response.status_code}")
        print(f"📥 Response: {response.text[:500]}")
        
        if response.status_code == 200:
            token_data = response.json()
            
            if 'access_token' in token_data:
                # Store token in session
                session['access_token'] = token_data['access_token']
                session['refresh_token'] = token_data.get('refresh_token')
                session['expires_in'] = token_data.get('expires_in')
                
                print(f"✅ Successfully obtained access token!")
                
                return f"""
                <html>
                <head>
                    <title>✅ TikTok Connected!</title>
                    <style>
                        body {{
                            font-family: Arial, sans-serif;
                            margin: 40px;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            color: white;
                            text-align: center;
                        }}
                        .success-card {{
                            background: rgba(255, 255, 255, 0.95);
                            color: #333;
                            padding: 40px;
                            border-radius: 20px;
                            margin: 50px auto;
                            max-width: 600px;
                            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                        }}
                        .btn {{
                            display: inline-block;
                            padding: 15px 30px;
                            background: #FF0050;
                            color: white;
                            text-decoration: none;
                            border-radius: 10px;
                            font-weight: bold;
                            margin: 20px 10px;
                            transition: transform 0.2s;
                        }}
                        .btn:hover {{
                            transform: translateY(-2px);
                            background: #e00040;
                        }}
                    </style>
                </head>
                <body>
                    <div class="success-card">
                        <h1 style="color: #28a745; font-size: 2.5em;">🎉 Success!</h1>
                        <p style="font-size: 1.2em;">Your TikTok account has been successfully connected!</p>
                        
                        <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin: 30px 0;">
                            <h3>📊 Connection Details:</h3>
                            <p><strong>Access Token:</strong> {token_data['access_token'][:30]}...</p>
                            <p><strong>Expires in:</strong> {token_data.get('expires_in', 'Unknown')} seconds</p>
                            <p><strong>Scope:</strong> {token_data.get('scope', 'Not specified')}</p>
                        </div>
                        
                        <div>
                            <a href="/" class="btn">🚀 Go to Dashboard</a>
                            <a href="/upload-video" class="btn" style="background: #28a745;">🎬 Upload Video</a>
                        </div>
                        
                        <p style="margin-top: 30px; color: #666; font-size: 0.9em;">
                            You can now upload Quran videos directly to TikTok!
                        </p>
                    </div>
                    
                    <script>
                        // Auto-redirect after 5 seconds
                        setTimeout(function() {{
                            window.location.href = '/';
                        }}, 5000);
                    </script>
                </body>
                </html>
                """
            else:
                return f"""
                <html>
                <body style="font-family: Arial; margin: 40px;">
                    <h1>❌ Token Error</h1>
                    <div style="background: #fff3cd; padding: 20px; border-radius: 8px;">
                        <p>No access_token in response:</p>
                        <pre>{json.dumps(token_data, indent=2)}</pre>
                    </div>
                    <p><a href="/">← Back to Home</a></p>
                </body>
                </html>
                """
        else:
            return f"""
            <html>
            <body style="font-family: Arial; margin: 40px;">
                <h1>❌ Token Exchange Failed</h1>
                <div style="background: #f8d7da; padding: 20px; border-radius: 8px;">
                    <p><strong>Status Code:</strong> {response.status_code}</p>
                    <p><strong>Response:</strong></p>
                    <pre>{response.text}</pre>
                </div>
                <p><a href="/">← Back to Home</a></p>
            </body>
            </html>
            """
            
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"❌ Exception in callback: {error_details}")
        
        return f"""
        <html>
        <body style="font-family: Arial; margin: 40px;">
            <h1>❌ Server Error</h1>
            <div style="background: #f8d7da; padding: 20px; border-radius: 8px;">
                <p><strong>Error:</strong> {str(e)}</p>
                <pre>{error_details}</pre>
            </div>
            <p><a href="/">← Back to Home</a></p>
        </body>
        </html>
        """        
@app.route('/test')
def test():
    return jsonify({
        'status': 'online',
        'app': 'q-hszm.onrender.com',
        'timestamp': datetime.now().isoformat()
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
        return redirect('/upload-video')
    
    return redirect('/upload-video')
def get_auth_url(self):
    """Generate TikTok OAuth URL with PKCE"""
    try:
        # Generate PKCE code verifier and challenge
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        
        # Store code_verifier in session for later use
        session['code_verifier'] = code_verifier
        
        # Make sure redirect_uri is properly URL-encoded
        from urllib.parse import quote
        encoded_redirect_uri = quote(self.redirect_uri, safe='')
        
        auth_url = (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={self.client_key}"
            "&scope=user.info.basic,video.upload,video.list"
            "&response_type=code"
            f"&redirect_uri={encoded_redirect_uri}"
            f"&code_challenge={code_challenge}"
            "&code_challenge_method=S256"
            "&state=tiktok_auth_quran_app"
        )
        print(f"🔗 Generated Auth URL (truncated): {auth_url[:200]}...")
        return auth_url
    except Exception as e:
        print(f"❌ Error generating auth URL: {e}")
        raise e
    
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
