from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import tensorflow as tf
import numpy as np
import pickle
import re
import tldextract
import subprocess
import json
import os
import sys
from pathlib import Path

# Debug prints (optional – remove in prod)
print(f"Current dir: {os.getcwd()}")
print(f"Sys path before: {sys.path}")

# Add dom_analyzer to path
dom_path = os.path.join(os.path.dirname(__file__), 'dom_analyzer')
if dom_path not in sys.path:
    sys.path.append(dom_path)
print(f"Added path: {dom_path}")

# Import DOM scorer
try:
    from dom_similarity import dom_score
    from visual_similarity import calculate_visual_score
    print("DOM & Visual scorers imported!")
except ImportError as e:
    print(f"DOM import error: {e}")
    raise

# Load URL Model (identical to standalone)
try:
    model = tf.keras.models.load_model("url_model/hybrid_best_model.keras")
    with open("url_model/tokenizer.pkl", "rb") as f:
        tokenizer = pickle.load(f)
    with open("url_model/url_feature_scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    print("URL model loaded!")
except Exception as e:
    print(f"URL load error: {e}")
    raise

# FastAPI App
app = FastAPI(title="Phishing Detector Web App")
app.mount("/static", StaticFiles(directory="static"), name="static")

class URLRequest(BaseModel):
    url: str
    brand: str = "paypal"

@app.get("/", response_class=HTMLResponse)
async def home():
    with open("static/index.html") as f:
        return f.read()

# URL Features (identical to standalone)
def extract_features(url):
    url = url.lower()
    if not url.startswith("http"):
        url = "http://" + url
    ext = tldextract.extract(url)
    domain = ext.domain
    suffix = ext.suffix
    hostname = domain + "." + suffix if suffix else domain
    return {
        "url_length": len(url),
        "count_digits": sum(c.isdigit() for c in url),
        "count_special": sum(c in "-@_./=:" for c in url),
        "has_login": int("login" in url),
        "has_secure": int("secure" in url),
        "has_bank": int("bank" in url),
        "tld_is_suspicious": int(suffix in ["xyz", "top", "help", "club"]),
        "is_ip": int(bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname))),
        "subdomain_count": ext.subdomain.count(".") + (1 if ext.subdomain else 0)
    }

# Phase 1: URL Score (identical to standalone – default padding='pre')
def get_url_score(url):
    seq = tokenizer.texts_to_sequences([url])
    padded = tf.keras.preprocessing.sequence.pad_sequences(seq, maxlen=200)  # Default 'pre' to match standalone
    feat = np.array([list(extract_features(url).values())])
    feat = scaler.transform(feat)
    pred = model.predict([padded, feat])[0][0]
    return float(pred)

# Phase 2: DOM Extraction & Score
def extract_dom_via_puppeteer(url, output_path="temp_dom.json"):
    puppeteer_path = "dom_analyzer/puppeteer_script.js"
    try:
        print(f"Running subprocess for URL: {url}")
        result = subprocess.run(["node", puppeteer_path, url, output_path], 
                                check=True, timeout=60, 
                                capture_output=True, text=True)
        print(f"Subprocess stdout: {result.stdout[:500]}...")
        
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                dom_tree = json.load(f)
            print(f"Tree loaded! Size: {len(json.dumps(dom_tree)) / 1000:.1f} KB")
            # Caller is responsible for cleanup now
            return dom_tree
        else:
            print("Temp file not created!")
            return None
    except subprocess.TimeoutExpired:
        print("Subprocess timeout!")
        return None
    except Exception as e:
        print(f"Subprocess error: {e}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return None

def get_dom_score(url, brand):
    # Define paths
    debug_dir = "static/debug_visuals"
    if not os.path.exists(debug_dir):
        os.makedirs(debug_dir)
        
    temp_test_path = "temp_test_dom.json"
    temp_brand_path = "temp_brand_dom.json"
    temp_test_img = os.path.join(debug_dir, "temp_test_dom.png")
    temp_brand_img = os.path.join(debug_dir, "temp_brand_dom.png")

    # Fetch test tree & screenshot
    dom_tree = extract_dom_via_puppeteer(url, temp_test_path)
    if not dom_tree:
        return None, None  # Signal failure instead of neutral score
    
    # Move screenshot if it was created in root (puppeteer script default)
    # The puppeteer script saves to outputFile.replace('.json', '.png')
    # So if temp_test_path is "temp_test_dom.json", img is "temp_test_dom.png"
    # We need to move it to our debug dir
    root_test_img = temp_test_path.replace('.json', '.png')
    if os.path.exists(root_test_img):
        os.rename(root_test_img, temp_test_img)
    
    # Fetch brand tree & screenshot
    brand_url = f"https://www.{brand}.com"
    brand_tree = extract_dom_via_puppeteer(brand_url, temp_brand_path)
    
    # Move brand screenshot
    root_brand_img = temp_brand_path.replace('.json', '.png')
    if os.path.exists(root_brand_img):
        os.rename(root_brand_img, temp_brand_img)

    if not brand_tree:
        # Cleanup test files if brand fails
        if os.path.exists(temp_test_path): os.remove(temp_test_path)
        if os.path.exists(temp_test_path): os.remove(temp_test_path)
        return None, None
    
    # Compute DOM score
    d_score = dom_score(temp_test_path, temp_brand_path)
    
    # Compute Visual score
    v_score = calculate_visual_score(temp_test_img, temp_brand_img)
    print(f"Visual Score: {v_score:.4f}")

    # Cleanup JSONs but KEEP images for debug
    for f in [temp_test_path, temp_brand_path]:
        if os.path.exists(f):
            os.remove(f)
    
    return d_score, v_score

# Phase 3: Fusion (URL + DOM + Visual)
def fuse_scores(url_score, dom_score, visual_score, brand):
    # Logic:
    # URL Score: High = Phishing (from model)
    # DOM Score: High = Identical Structure (Phishing if domain mismatch)
    # Visual Score: High = Identical Visuals (Phishing if domain mismatch)
    
    # Weights: URL(10%), DOM(45%), Visual(45%)
    URL_WEIGHT = 0.10
    DOM_WEIGHT = 0.45
    VISUAL_WEIGHT = 0.45
    
    # If visual score is missing (e.g. 0.0 or failed), redistribute weight to DOM
    if visual_score == 0.0:
        DOM_WEIGHT += VISUAL_WEIGHT
        VISUAL_WEIGHT = 0.0
    
    hybrid = (URL_WEIGHT * url_score) + (DOM_WEIGHT * dom_score) + (VISUAL_WEIGHT * visual_score)
    
    # Threshold logic
    # If hybrid score is HIGH, it means it looks/acts like the target brand.
    # If domain mismatch was already applied (penalty), the scores might be lower.
    # Wait, the penalty logic in predict() REDUCES the score if domain mismatch.
    # So:
    # - Real Brand: High Score (1.0) -> Domain Match -> No Penalty -> High Hybrid -> Legitimate?
    # - Phishing: High Score (1.0) -> Domain Mismatch -> Penalty (0.5) -> Low Hybrid -> Phishing?
    
    # Let's align with the user's request: "url model is higher for phishing"
    # Usually:
    # 0.0 = Safe / Different
    # 1.0 = Phishing / Identical (for URL model)
    
    # But for DOM/Visual:
    # 1.0 = Identical to Brand.
    # If Domain Match = True, then 1.0 is GOOD (It IS the brand).
    # If Domain Match = False, then 1.0 is BAD (It is a clone).
    
    # The predict() function applies a penalty if domain mismatch.
    # dom_score = dom_score_raw * dom_penalty (0.5)
    
    # So if Phishing site (Identical, 1.0) -> Penalty -> 0.5.
    # If Safe site (Different, 0.0) -> Penalty -> 0.0.
    # If Real Brand (Identical, 1.0) -> No Penalty -> 1.0.
    
    # This implies:
    # High Hybrid (> 0.8) = Legitimate (It is the brand)
    # Mid Hybrid (~0.5) = Phishing (It looks like brand but wrong domain)
    # Low Hybrid (< 0.3) = Legitimate (Random site, doesn't look like brand)
    
    # This is tricky. Let's simplify based on standard Phishing detection:
    # We want a "Phishing Probability".
    # URL Model: 1.0 = Phishing.
    # Visual/DOM: 1.0 = Identical.
    
    # If Domain Mismatch AND High Visual/DOM -> Phishing Probability = HIGH.
    # If Domain Match AND High Visual/DOM -> Phishing Probability = LOW.
    
    # Let's rework the fusion to return a "Phishing Probability".
    
    # We need to pass 'is_domain_match' to this function or handle it before.
    # The current architecture passes scores that are already penalized.
    # Let's stick to the current flow but fix the interpretation.
    
    # Current flow in predict():
    # if not domain_match: penalty = 0.5
    # dom = raw * penalty
    
    # If Phishing (Clone): Raw=1.0 * 0.5 = 0.5. Hybrid ~= 0.5.
    # If Real Brand: Raw=1.0 * 1.0 = 1.0. Hybrid ~= 1.0.
    # If Random Site: Raw=0.0 * 0.5 = 0.0. Hybrid ~= 0.0.
    
    # So Phishing is in the middle? That's not ideal for a simple threshold.
    
    # ALTERNATIVE LOGIC (Better):
    # Calculate Similarity (0 to 1).
    # If Similarity is High AND Domain is Mismatch -> Phishing.
    # If Similarity is High AND Domain is Match -> Legitimate.
    # If Similarity is Low -> Legitimate (not targeting this brand).
    
    # Since we can't easily change the whole flow in one edit, let's adjust the thresholding here.
    # We will assume the caller (predict) handles the "Phishing" determination logic better,
    # OR we return the raw similarity here and let predict decide.
    
    # But `fuse_scores` returns the label.
    # Let's try this:
    # The caller `predict` has `is_domain_match`.
    # Let's assume `fuse_scores` just calculates a "Similarity Score".
    
    # We will return the hybrid score. The LABEL generation should happen in `predict` ideally,
    # but since it's here, let's make it generic.
    
    threshold = 0.7 # High similarity
    
    # We can't determine Phishing vs Legit purely on score without knowing if domain matched.
    # But wait, `predict` calls this.
    # Let's just return the score and let `predict` handle the label? 
    # The function signature expects label.
    
    # Let's keep it simple:
    # We will return the Hybrid Score (Similarity to Brand).
    # The Label will be determined by the caller? No, the caller expects label from here.
    
    # Okay, I will change `predict` to pass `is_domain_match` to `fuse_scores`?
    # Or I can just return the score and move logic to `predict`.
    # I'll stick to the plan: "Invert threshold check" was the plan, but that assumes High=Phishing.
    
    # Let's make `fuse_scores` just return the score, and I'll update `predict` to do the logic.
    # But I can only edit one block.
    
    # I will update `fuse_scores` to take `is_domain_match` (I can't change signature easily without changing caller).
    # Actually, I am editing `app.py` so I CAN change both if they are in the file.
    # The `predict` function is below this block.
    
    # I will change `fuse_scores` to just return the score, and I will update `predict` in a separate edit 
    # (or if I can capture it in one go).
    # `predict` is lines 174+. My edit ends at 172.
    # I will extend the edit to include `predict`.
    
    return round(hybrid, 4), "See_Predict_Logic", threshold
# Predict Endpoint
@app.post("/predict")
def predict(data: URLRequest):
    try:
        url = data.url
        brand = data.brand.lower()
        # Domain validation
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower()
        expected_domain = f"{brand}.com"  # Simple match (expand for www, etc.)
        is_domain_match = expected_domain in domain

        url_score = get_url_score(url)
        dom_score, visual_score = get_dom_score(url, brand)
        
        # Fusion Logic
        if dom_score is None:
            # Site Unreachable -> Rely 100% on URL Model
            print("DEBUG: Site Unreachable. Fallback to URL Model.")
            dom_score = 0.0
            visual_score = 0.0
            similarity_score = 0.0
            phishing_prob = url_score
        else:
            # Site Reachable -> Hybrid Logic
            # 1. Calculate Structural/Visual Similarity to the Brand (0.0 to 1.0)
            #    If visual_score is 0 (failed), rely on DOM.
            if visual_score > 0:
                similarity_score = (dom_score * 0.5) + (visual_score * 0.5)
            else:
                similarity_score = dom_score
                
            # 2. Determine Phishing Probability
            #    - URL Model: 1.0 = Phishing
            #    - Similarity: 1.0 = Identical to Brand
            
            if is_domain_match:
                # If it IS the brand, high similarity is GOOD. 
                # Phishing probability relies mostly on URL anomalies (rare for real brand)
                # We trust the domain match heavily.
                phishing_prob = url_score * 0.1 # Very low probability even if URL model is paranoid
            else:
                # If it is NOT the brand:
                # - High Similarity = High Phishing Probability (Clone)
                # - Low Similarity = Low Phishing Probability (Just a random other site)
                
                # Weight: 20% URL Model, 80% Similarity (Clones are dangerous)
                phishing_prob = (url_score * 0.2) + (similarity_score * 0.8)

        print(f"DEBUG: URL={url}, Brand={brand}")
        print(f"DEBUG: Domain Match={is_domain_match}")
        print(f"DEBUG: URL Score={url_score}")
        print(f"DEBUG: DOM Score={dom_score}")
        print(f"DEBUG: Visual Score={visual_score}")
        print(f"DEBUG: Similarity Score={similarity_score}")
        print(f"DEBUG: Phishing Prob (Hybrid)={phishing_prob}")

        threshold = 0.5
        label = "Phishing" if phishing_prob > threshold else "Legitimate"
        
        return {
            "url": url,
            "brand": brand,
            "domain_match": is_domain_match,
            "url_score": url_score,
            "dom_score": dom_score,
            "visual_score": visual_score,
            "similarity_score": round(similarity_score, 4),
            "hybrid_score": round(phishing_prob, 4), # Renamed for frontend compatibility
            "threshold": threshold,
            "final_label": label
        }
    except Exception as e:
        return {"error": f"Prediction failed: {str(e)}"}