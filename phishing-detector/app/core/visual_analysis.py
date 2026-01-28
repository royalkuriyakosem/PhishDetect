from skimage.metrics import structural_similarity as ssim
import cv2
import numpy as np
import os

def calculate_visual_score(image_path1, image_path2):
    """
    Calculates the Structural Similarity Index (SSIM) between two images.
    Returns a score between 0.0 (different) and 1.0 (identical).
    """
    if not os.path.exists(image_path1) or not os.path.exists(image_path2):
        print(f"Error: One or both images not found: {image_path1}, {image_path2}")
        return 0.0

    # Load images
    img1 = cv2.imread(image_path1)
    img2 = cv2.imread(image_path2)

    if img1 is None or img2 is None:
        print("Error: Failed to load images.")
        return 0.0

    # Convert to grayscale
    gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)

    # Resize img2 to match img1 dimensions for SSIM
    if gray1.shape != gray2.shape:
        gray2 = cv2.resize(gray2, (gray1.shape[1], gray1.shape[0]))

    # Compute SSIM
    score, _ = ssim(gray1, gray2, full=True)
    
    return float(score)
