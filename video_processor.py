# video_processor.py
import os
from moviepy.editor import VideoFileClip
import time

class VideoProcessor:
    def __init__(self):
        self.processed_dir = "videos/processed"
        os.makedirs(self.processed_dir, exist_ok=True)
    
    def process_video(self, input_path):
        """Process video for TikTok requirements"""
        try:
            # Generate output filename
            timestamp = int(time.time())
            output_path = os.path.join(self.processed_dir, f"processed_{timestamp}.mp4")
            
            # Load video
            clip = VideoFileClip(input_path)
            
            # Basic processing for TikTok
            # 1. Ensure vertical format (9:16)
            target_ratio = 9/16
            current_ratio = clip.w / clip.h
            
            if current_ratio > target_ratio:
                # Video is too wide, crop sides
                target_width = int(clip.h * target_ratio)
                x_center = clip.w / 2
                cropped_clip = clip.crop(
                    x1=x_center - target_width/2,
                    width=target_width
                )
            else:
                # Video is too tall, crop top/bottom
                target_height = int(clip.w / target_ratio)
                y_center = clip.h / 2
                cropped_clip = clip.crop(
                    y1=y_center - target_height/2,
                    height=target_height
                )
            
            # 2. Ensure reasonable duration (max 3 minutes)
            if cropped_clip.duration > 180:
                cropped_clip = cropped_clip.subclip(0, 180)
            
            # 3. Export with TikTok-friendly settings
            cropped_clip.write_videofile(
                output_path,
                codec='libx264',
                audio_codec='aac',
                temp_audiofile='temp-audio.m4a',
                remove_temp=True,
                bitrate="5000k"
            )
            
            # Close clips to free memory
            clip.close()
            cropped_clip.close()
            
            return output_path
            
        except Exception as e:
            print(f"Video processing error: {e}")
            # If processing fails, return original
            return input_path