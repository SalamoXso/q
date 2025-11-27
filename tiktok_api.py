# tiktok_api.py
import requests
import json
from config import Config

class TikTokAPI:
    def __init__(self):
        self.client_key = Config.CLIENT_KEY
        self.client_secret = Config.CLIENT_SECRET
        self.redirect_uri = Config.REDIRECT_URI
        self.base_url = "https://open.tiktokapis.com/v2"
    
    def get_auth_url(self):
        """Generate TikTok OAuth URL"""
        auth_url = (
            f"https://www.tiktok.com/v2/auth/authorize/"
            f"?client_key={self.client_key}"
            "&scope=user.info.basic,video.upload,video.list"  # Request upload permissions
            "&response_type=code"
            f"&redirect_uri={self.redirect_uri}"
        )
        return auth_url
    
    def exchange_code_for_token(self, auth_code):
        """Exchange authorization code for access token"""
        token_url = f"{self.base_url}/oauth/token/"
        
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
    
    def upload_video(self, access_token, video_path, caption):
        """Upload video to TikTok"""
        # Note: This endpoint might not be available in sandbox
        upload_url = f"{self.base_url}/video/upload/"
        
        headers = {
            'Authorization': f'Bearer {access_token}',
        }
        
        # Prepare the file and data
        try:
            with open(video_path, 'rb') as video_file:
                files = {
                    'video': video_file
                }
                data = {
                    'caption': caption
                }
                
                response = requests.post(upload_url, headers=headers, files=files, data=data)
                return response.json()
                
        except Exception as e:
            return {'error': f'Upload failed: {str(e)}'}
    
    def check_status(self, access_token):
        """Check API status and user info"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        # Try to get user info first
        user_url = f"{self.base_url}/user/info/"
        user_response = requests.get(user_url, headers=headers)
        
        return {
            'user_info': user_response.json() if user_response.status_code == 200 else 'Failed',
            'authenticated': user_response.status_code == 200
        }