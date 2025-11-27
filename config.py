# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    CLIENT_KEY = os.getenv('TIKTOK_CLIENT_KEY')
    CLIENT_SECRET = os.getenv('TIKTOK_CLIENT_SECRET')
    REDIRECT_URI = os.getenv('REDIRECT_URI')
    ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
    
    # Video settings
    VIDEO_SETTINGS = {
        'max_duration': 180,  # 3 minutes max
        'supported_formats': ['.mp4', '.mov', '.avi'],
        'max_file_size': 500 * 1024 * 1024  # 500MB
    }