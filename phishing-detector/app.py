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
    print("DOM scorer imported!")
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
def extract_dom_via_puppeteer(url):
    puppeteer_path = "dom_analyzer/puppeteer_script.js"
    temp_dom = "temp_dom.json"
    try:
        print(f"Running subprocess for URL: {url}")
        result = subprocess.run(["node", puppeteer_path, url, temp_dom], 
                                check=True, timeout=60, 
                                capture_output=True, text=True)  # Capture stdout/stderr
        print(f"Subprocess stdout: {result.stdout[:500]}...")  # First 500 chars
        print(f"Subprocess stderr: {result.stderr}")
        if os.path.exists(temp_dom):
            with open(temp_dom, "r") as f:
                dom_tree = json.load(f)
            print(f"Tree loaded! Size: {len(json.dumps(dom_tree)) / 1000:.1f} KB")
            os.remove(temp_dom)
            return dom_tree
        else:
            print("Temp file not created!")
            return None
    except subprocess.TimeoutExpired:
        print("Subprocess timeout!")
        return None
    except Exception as e:
        print(f"Subprocess error: {e}")
        if os.path.exists(temp_dom):
            os.remove(temp_dom)
        return None

def get_dom_score(url, brand):
    # Fetch test tree (from user URL)
    dom_tree = extract_dom_via_puppeteer(url)
    if not dom_tree:
        return 0.5  # Neutral fallback
    
    # Fetch brand tree live (your idea – dynamic baseline)
    brand_url = f"https://www.{brand}.com"  # Adjust for www. or subdomains if needed
    brand_tree = extract_dom_via_puppeteer(brand_url)
    if not brand_tree:
        return 0.5  # Fallback if brand fetch fails
    
    # Save both to temp for comparison
    temp_test_path = "temp_test_dom.json"
    temp_brand_path = "temp_brand_dom.json"
    with open(temp_test_path, "w") as f:
        json.dump(dom_tree, f)
    with open(temp_brand_path, "w") as f:
        json.dump(brand_tree, f)
    
    # Compute score
    score = dom_score(temp_test_path, temp_brand_path)
    
    # Cleanup
    os.remove(temp_test_path)
    os.remove(temp_brand_path)
    
    return score

# Phase 3: Fusion (DOM-heavy: 0.1 URL + 0.9 DOM)
def fuse_scores(url_score, dom_score, brand):
    if dom_score < 0.45:
        return 0.35, "Phishing", 0.40          # Changed from 0.92 → 0.35 (below 0.40)
    
    DOM_WEIGHT = 0.90
    URL_WEIGHT = 0.10
    
    hybrid = DOM_WEIGHT * dom_score
    
    if url_score <= 0.5:
        hybrid += URL_WEIGHT * (1.0 - url_score)
    else:
        phishing_strength = url_score - 0.5
        hybrid -= URL_WEIGHT * (phishing_strength * 2)
    
    hybrid = max(0.0, min(1.0, hybrid))
    
    # FINAL CHANGE: If label is Phishing → force hybrid < 0.40
    label = "Phishing" if (hybrid < 0.40 or dom_score < 0.45) else "Legitimate"
    if label == "Phishing":
        hybrid = min(hybrid, 0.39)  # Ensures fusion score is ALWAYS < 0.40 when Phishing
    
    return round(hybrid, 4), label, 0.40
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
        if not is_domain_match:
            print(f"Domain mismatch: {domain} vs {expected_domain} – Penalizing DOM")
            dom_penalty = 0.5  # Halve DOM score for typos/suspicious
        else:
            dom_penalty = 1.0

        url_score = get_url_score(url)
        dom_score = get_dom_score(url, brand) * dom_penalty  # Apply penalty
        hybrid_score, label, threshold = fuse_scores(url_score, dom_score, brand)
        return {
            "url": url,
            "brand": brand,
            "domain_match": is_domain_match,
            "url_score": url_score,
            "dom_score": dom_score,
            "hybrid_score": hybrid_score,
            "threshold": threshold,
            "final_label": label
        }
    except Exception as e:
        return {"error": f"Prediction failed: {str(e)}"}