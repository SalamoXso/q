# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    CLIENT_KEY = os.getenv('TIKTOK_CLIENT_KEY')
    CLIENT_SECRET = os.getenv('TIKTOK_CLIENT_SECRET')
    
    # Use Render URL since localhost is not supported
    REDIRECT_URI = 'https://q-hszm.onrender.com/callback'
    
    @classmethod
    def validate_config(cls):
        missing = []
        if not cls.CLIENT_KEY or cls.CLIENT_KEY == 'your_client_key_here':
            missing.append('TIKTOK_CLIENT_KEY')
        if not cls.CLIENT_SECRET or cls.CLIENT_SECRET == 'your_client_secret_here':
            missing.append('TIKTOK_CLIENT_SECRET')
        
        if missing:
            raise Exception(f"Missing environment variables: {', '.join(missing)}")

# Validate configuration
try:
    Config.validate_config()
    print("✅ Configuration validated successfully")
    print(f"🔧 Redirect URI: {Config.REDIRECT_URI}")
except Exception as e:
    print(f"❌ Configuration error: {e}")