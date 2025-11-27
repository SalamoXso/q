# app.py
from flask import Flask, render_template, request, jsonify, redirect, session
import json
import os
from tiktok_api import TikTokAPI
from video_processor import VideoProcessor

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this!

# Initialize API and processor
tiktok_api = TikTokAPI()
video_processor = VideoProcessor()

@app.route('/')
def home():
    """Main dashboard"""
    return """
    <html>
        <body>
            <h1>Quran TikTok Uploader</h1>
            <p>Welcome to your TikTok automation tool!</p>
            
            <h2>Quick Actions:</h2>
            <ul>
                <li><a href="/auth">1. Authenticate with TikTok</a></li>
                <li><a href="/upload-form">2. Upload a Video</a></li>
                <li><a href="/status">3. Check API Status</a></li>
            </ul>
        </body>
    </html>
    """

@app.route('/auth')
def authenticate():
    """Start TikTok authentication"""
    auth_url = tiktok_api.get_auth_url()
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Handle TikTok callback after authentication"""
    auth_code = request.args.get('code')
    
    if auth_code:
        # Exchange code for access token
        token_data = tiktok_api.exchange_code_for_token(auth_code)
        
        if 'access_token' in token_data:
            # Save the access token
            session['access_token'] = token_data['access_token']
            return f"""
            <h2>Authentication Successful! 🎉</h2>
            <p>Access Token: {token_data['access_token'][:50]}...</p>
            <p><a href="/upload-form">Start Uploading Videos</a></p>
            """
        else:
            return f"Authentication failed: {token_data}"
    
    return "No authorization code received"

@app.route('/upload-form')
def upload_form():
    """Show video upload form"""
    return """
    <html>
        <body>
            <h2>Upload Quran Video to TikTok</h2>
            <form action="/upload" method="post" enctype="multipart/form-data">
                <p>Select Video: <input type="file" name="video" accept="video/*"></p>
                <p>Caption: <textarea name="caption" rows="3" cols="50" 
                    placeholder="Enter your caption with hashtags..."></textarea></p>
                <p><input type="submit" value="Upload to TikTok"></p>
            </form>
            
            <p><a href="/">← Back to Home</a></p>
        </body>
    </html>
    """

@app.route('/upload', methods=['POST'])
def upload_video():
    """Handle video upload to TikTok"""
    try:
        # Get uploaded file
        video_file = request.files['video']
        caption = request.form['caption']
        
        if not video_file:
            return "No video file selected"
        
        # Save uploaded file temporarily
        temp_path = f"videos/raw/temp_{video_file.filename}"
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        video_file.save(temp_path)
        
        # Process video
        processed_path = video_processor.process_video(temp_path)
        
        # Upload to TikTok
        access_token = session.get('access_token')
        if not access_token:
            return "Please authenticate first! <a href='/auth'>Authenticate here</a>"
        
        result = tiktok_api.upload_video(access_token, processed_path, caption)
        
        # Clean up temp files
        os.remove(temp_path)
        if os.path.exists(processed_path):
            os.remove(processed_path)
        
        return f"""
        <h2>Upload Result</h2>
        <pre>{json.dumps(result, indent=2)}</pre>
        <p><a href="/upload-form">Upload Another Video</a></p>
        """
        
    except Exception as e:
        return f"Error during upload: {str(e)}"

@app.route('/status')
def api_status():
    """Check TikTok API status"""
    access_token = session.get('access_token')
    if access_token:
        status = tiktok_api.check_status(access_token)
        return jsonify(status)
    return "Not authenticated"

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('videos/raw', exist_ok=True)
    os.makedirs('videos/processed', exist_ok=True)
    
    app.run(host='0.0.0.0', port=5000, debug=True)