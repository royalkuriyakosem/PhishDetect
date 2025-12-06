from fastapi import FastAPI
import tensorflow as tf
import numpy as np
import pickle
import re
import tldextract
from pydantic import BaseModel

# ----------------------------------
# Load Model, Tokenizer, Scaler
# ----------------------------------
model = tf.keras.models.load_model("hybrid_best_model.keras")

with open("tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

with open("url_feature_scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

MAX_LEN = 200

# ----------------------------------
# Feature Extraction (SAME AS TRAINING)
# ----------------------------------
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

# ----------------------------------
# FastAPI App
# ----------------------------------
app = FastAPI(title="Hybrid Phishing Detection API")

class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"status": "Hybrid Phishing Detection API Running"}

@app.post("/predict")
def predict(data: URLRequest):
    url = data.url

    # ---- Text Tokenization ----
    seq = tokenizer.texts_to_sequences([url])
    padded = tf.keras.preprocessing.sequence.pad_sequences(seq, maxlen=MAX_LEN)

    # ---- Feature Extraction ----
    feat = np.array([list(extract_features(url).values())])
    feat = scaler.transform(feat)

    # ---- Model Prediction ----
    pred = model.predict([padded, feat])[0][0]

    result = "phishing" if pred > 0.5 else "legitimate"

    return {
        "url": url,
        "prediction": result,
        "confidence": float(pred)
    }
