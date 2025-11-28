# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Use environment variables from Render
    CLIENT_KEY = os.getenv('TIKTOK_CLIENT_KEY')
    CLIENT_SECRET = os.getenv('TIKTOK_CLIENT_SECRET')
    REDIRECT_URI = os.getenv('REDIRECT_URI', 'https://q-hszm.onrender.com/callback')
    ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
    
    # Video settings
    VIDEO_SETTINGS = {
        'max_duration': 180,
        'supported_formats': ['.mp4', '.mov', '.avi'],
        'max_file_size': 500 * 1024 * 1024
    }