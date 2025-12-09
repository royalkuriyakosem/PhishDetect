# PhishDetect: Comprehensive Project Guide

## 1. Project Goal
**PhishDetect** is a hybrid phishing detection framework that combines three distinct analysis methods to identify malicious websites:
1.  **URL Analysis**: Uses Machine Learning to detect suspicious patterns in the URL string itself.
2.  **DOM Analysis**: Compares the HTML structure (DOM) of the target site against a legitimate brand's structure.
3.  **Visual Analysis**: Compares the visual appearance (screenshot) of the target site against the legitimate brand.

The system fuses these scores to provide a final **Phishing Probability**.

---

## 2. Architecture Overview

```mermaid
graph TD
    User[User Browser] -->|URL + Brand| Frontend[Frontend (HTML/JS)]
    Frontend -->|POST /predict| API[FastAPI Server (app.py)]
    
    API -->|1. Extract Features| URLModel[URL Model (Keras)]
    API -->|2. Launch Browser| Puppeteer[Puppeteer Script (Node.js)]
    
    Puppeteer -->|Capture DOM & Screenshot| TargetData[Target Site Data]
    Puppeteer -->|Capture DOM & Screenshot| BrandData[Brand Site Data]
    
    API -->|3. Compare DOMs| DOMEngine[DOM Similarity Engine]
    API -->|4. Compare Images| VisualEngine[Visual Similarity Engine]
    
    URLModel -->|Score| Fusion[Fusion Logic]
    DOMEngine -->|Score| Fusion
    VisualEngine -->|Score| Fusion
    
    Fusion -->|Final Probability| Frontend
```

---

## 3. File-by-File Breakdown

### Root Directory
- **`app.py`**: The **Brain** of the operation.
    - Runs the FastAPI web server.
    - Loads the ML model (`url_model`).
    - Orchestrates the analysis:
        1.  Calculates URL Score.
        2.  Calls `puppeteer_script.js` to scrape the website.
        3.  Calls `dom_similarity.py` and `visual_similarity.py` to compare results.
        4.  Fuses all scores into a final decision.
- **`requirements.txt`**: Lists all Python dependencies (FastAPI, TensorFlow, OpenCV, etc.).

### `static/` (Frontend)
- **`index.html`**: The user interface. Contains the form and result cards.
- **`style.css`**: "Cyber Security" theme styling (Dark mode, Glassmorphism, Neon effects).
- **`script.js`**: Handles user interaction. Sends the URL to the backend and updates the UI with results.

### `url_model/` (Phase 1: URL Analysis)
- **`hybrid_best_model.keras`**: The pre-trained Deep Learning model (CNN/LSTM) that predicts phishing based on URL characters.
- **`tokenizer.pkl`**: Converts URL characters into numbers the model can understand.
- **`url_feature_scaler.pkl`**: Scales numerical features (like URL length) for the model.

### `dom_analyzer/` (Phase 2 & 3: Content Analysis)
- **`puppeteer_script.js`**: A Node.js script that launches a headless Chrome browser. It visits the URL, extracts the DOM tree (HTML structure), and takes a screenshot.
- **`dom_similarity.py`**: Compares two DOM trees using **Tree Edit Distance**. It calculates how many "edits" (insertions, deletions) are needed to turn one site's structure into the other.
- **`visual_similarity.py`**: Compares two screenshots using **SSIM (Structural Similarity Index)**. It measures how visually identical the two sites are.
- **`tree_edit_distance.py`**: Helper script containing the algorithm for DOM comparison.
- **`brands/`**: (Optional) Can store pre-computed DOMs for brands to speed up analysis.

---

## 4. Data Flow: How it Works

1.  **Input**: User enters `http://faceb00k.com` and selects "Facebook".
2.  **URL Analysis**:
    - `app.py` extracts features (length, special chars) and feeds them to `hybrid_best_model.keras`.
    - **Result**: High Phishing Probability (e.g., 0.95) because of the typo "00".
3.  **Content Extraction**:
    - `app.py` runs `node puppeteer_script.js` for both the Target (`faceb00k.com`) and the Real Brand (`facebook.com`).
    - **Output**: JSON files (DOM structure) and PNG images (Screenshots).
4.  **Comparison**:
    - **DOM**: `dom_similarity.py` compares the JSONs. If `faceb00k.com` is a clone, the structure will be very similar (Score ~1.0).
    - **Visual**: `visual_similarity.py` compares the PNGs. If it looks like Facebook, Score ~1.0.
5.  **Fusion**:
    - `app.py` combines the scores.
    - **Logic**:
        - If Site Unreachable: Rely on URL Score.
        - If Site Reachable:
            - **High Similarity** to Brand + **Domain Mismatch** = **PHISHING**.
            - **Low Similarity** to Brand = **SAFE** (just a random site).
            - **High Similarity** + **Domain Match** = **SAFE** (It is the real site).

---

## 5. Key Concepts
- **Phishing Probability**: The final score. **0.0** is Safe, **1.0** is Phishing.
- **Similarity Score**: How much the site looks/acts like the target brand. **1.0** means Identical.
- **Domain Match**: A critical check. If the domain matches the brand (e.g., `facebook.com`), we trust it, even if it looks identical (because it IS the real site).
