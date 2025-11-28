# video_processor.py (minimal version)
import os
import shutil

class VideoProcessor:
    def __init__(self):
        self.processed_dir = "videos/processed"
        os.makedirs(self.processed_dir, exist_ok=True)
    
    def process_video(self, input_path):
        """
        Minimal video processor - just validates file exists
        We'll add proper processing after basic app works
        """
        if os.path.exists(input_path):
            return input_path
        else:
            raise FileNotFoundError(f"Video file not found: {input_path}")