# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    CLIENT_KEY = os.getenv('TIKTOK_CLIENT_KEY')
    CLIENT_SECRET = os.getenv('TIKTOK_CLIENT_SECRET')
    
    # Try different formats - TikTok Sandbox can be picky
    REDIRECT_URI = 'http://127.0.0.1:5000/callback'  # Try IP instead of localhost
    
    # Alternative formats to try:
    # REDIRECT_URI = 'http://localhost:5000/callback'
    # REDIRECT_URI = 'http://localhost/callback'  # Without port
    # REDIRECT_URI = 'http://127.0.0.1/callback'  # Without port
    
    @classmethod
    def validate_config(cls):
        missing = []
        if not cls.CLIENT_KEY or cls.CLIENT_KEY == 'your_client_key_here':
            missing.append('TIKTOK_CLIENT_KEY')
        if not cls.CLIENT_SECRET or cls.CLIENT_SECRET == 'your_client_secret_here':
            missing.append('TIKTOK_CLIENT_SECRET')
        
        if missing:
            raise Exception(f"Missing environment variables: {', '.join(missing)}")