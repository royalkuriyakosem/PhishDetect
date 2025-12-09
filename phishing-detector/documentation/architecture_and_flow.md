# Project Architecture & Data Flow

## Overview
This Phishing Detector is a **Hybrid Security System** that combines three distinct analysis methods to determine if a website is legitimate or a phishing attempt. It uses a "Fusion" approach to weigh evidence from URL patterns, DOM structure, and Visual similarity.

## System Architecture

### 1. The Core (Orchestrator)
*   **File**: `app.py`
*   **Role**: The central brain of the application. It runs a FastAPI server that handles user requests, coordinates the analysis phases, and fuses the final scores.
*   **Key Functions**:
    *   `predict()`: Receives the URL, triggers analysis, and returns the verdict.
    *   `fuse_scores()`: The logic engine that combines different risk scores into a final probability.

### 2. The Eyes (Data Collection)
*   **File**: `dom_analyzer/puppeteer_script.js`
*   **Role**: A headless browser script (using Puppeteer) that visits websites like a real user.
*   **Actions**:
    *   Loads the URL.
    *   Extracts the DOM Tree (HTML structure).
    *   Captures a full-page Screenshot.
    *   Saves these as temporary files (`.json` and `.png`) for analysis.

### 3. The Analyzers (Intelligence)

#### A. URL Analysis (The Instinct)
*   **Folder**: `url_model/`
*   **Files**: `hybrid_best_model.keras`, `tokenizer.pkl`
*   **Role**: A Machine Learning model (TensorFlow/Keras) trained on millions of malicious and safe URLs.
*   **How it works**: It looks at the text of the URL itself (e.g., length, special characters, suspicious words like "login" or "secure") to predict danger before even visiting the site.

#### B. DOM Analysis (The Structural Analyst)
*   **File**: `dom_analyzer/dom_similarity.py` (imported as `dom_score`)
*   **Role**: Compares the *code structure* of the suspicious site against the real brand's site.
*   **How it works**: It converts the HTML tags into a tree structure and calculates how similar the nesting and tag usage are. A high score means the site's code is copied from the original.

#### C. Visual Analysis (The Visual Cortex)
*   **File**: `dom_analyzer/visual_similarity.py`
*   **Role**: Compares the *look and feel* of the suspicious site against the real brand's site.
*   **How it works**: Uses **SSIM (Structural Similarity Index)** to compare the screenshots pixel-by-pixel (ignoring minor color shifts). A high score means the site looks identical to the user.

## Data Flow: The Life of a Request

1.  **User Input**: User submits a URL (e.g., `http://fake-google.com`) and a Brand (e.g., `google`) via the Frontend (`static/index.html`).
2.  **API Request**: The frontend sends a POST request to `/predict` in `app.py`.
3.  **Phase 1: URL Check**:
    *   `app.py` runs the URL through the TensorFlow model.
    *   **Result**: `url_score` (0.0 to 1.0).
4.  **Phase 2: Data Extraction**:
    *   `app.py` calls `puppeteer_script.js` twice:
        *   Once for the **Suspicious URL**.
        *   Once for the **Real Brand URL** (e.g., `https://www.google.com`).
    *   **Output**: JSON DOM trees and PNG Screenshots are saved to `static/debug_visuals/`.
5.  **Phase 3: Deep Analysis**:
    *   `dom_similarity.py` compares the two JSON files. -> `dom_score`
    *   `visual_similarity.py` compares the two PNG files. -> `visual_score`
6.  **Phase 4: Fusion & Verdict**:
    *   `app.py` checks if the **Domain** matches the brand.
    *   **Logic**:
        *   If **Domain Match** (e.g., `google.com`): Trust the site.
        *   If **Domain Mismatch** + **High Visual/DOM Similarity**: FLAG AS PHISHING (Visual Clone).
    *   **Result**: `final_label` ("Legitimate" or "Phishing").
7.  **Response**: The JSON result is sent back to the frontend to display the risk level and scores.

## File Map
```text
/phishing-detector
├── app.py                      # MAIN SERVER & LOGIC
├── dom_analyzer/
│   ├── puppeteer_script.js     # BROWSER AUTOMATION (Screenshots/DOM)
│   ├── visual_similarity.py    # IMAGE COMPARISON
│   └── dom_similarity.py       # CODE STRUCTURE COMPARISON
├── url_model/                  # ML MODEL FILES
├── static/
│   ├── index.html              # USER INTERFACE
│   ├── script.js               # FRONTEND LOGIC
│   └── debug_visuals/          # GENERATED DEBUG IMAGES
└── documentation/              # YOU ARE HERE
```
