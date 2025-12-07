# Phishing Detector Project Overview

This project is a **Brand Verification System** designed to detect phishing attempts by comparing a suspicious URL against a known legitimate brand (e.g., PayPal). It uses a hybrid approach combining **URL feature analysis** and **DOM (Document Object Model) structural similarity**.

## 1. High-Level Architecture

The application is a web-based tool built with:
- **Frontend**: HTML/CSS/JS (Vanilla) for user input.
- **Backend**: Python (FastAPI) for processing requests.
- **Analysis Engines**:
    - **TensorFlow/Keras**: For URL string analysis.
    - **Puppeteer (Node.js)**: For headless browsing and DOM extraction.
    - **Tree Edit Distance**: For comparing page structures.

## 2. Workflow & Data Flow

1.  **User Input**: The user provides a `URL` (e.g., `http://fake-paypal.com`) and a target `Brand` (e.g., `paypal`).
2.  **Request**: The frontend sends a `POST /predict` request to the FastAPI backend.
3.  **Analysis Phase 1: URL Scoring**
    - The backend uses a pre-trained Keras model (`hybrid_best_model.keras`) to analyze the URL string itself.
    - It extracts features like URL length, special characters, and suspicious TLDs.
    - **Output**: A probability score (0.0 to 1.0) indicating how "legitimate" the URL string looks.
4.  **Analysis Phase 2: DOM Scoring**
    - The backend launches a headless Chrome browser using **Puppeteer**.
    - It visits the **Suspect URL** and extracts its DOM tree (HTML structure).
    - It also visits the **Official Brand URL** (e.g., `https://www.paypal.com`) and extracts its DOM tree.
    - It compares the two trees using a **Tree Edit Distance** algorithm.
    - **Output**: A similarity score (0.0 to 1.0). High score means the suspect site *visually/structurally resembles* the official brand site.
5.  **Analysis Phase 3: Domain Verification & Fusion**
    - The system checks if the suspect URL's domain matches the brand name.
        - If **Mismatch** (e.g., `fake-paypal.com` vs `paypal`): It applies a **penalty** (halves the DOM score).
    - It fuses the URL Score and the Penalized DOM Score.
    - **Logic**:
        - If the site looks like PayPal (High DOM Similarity) but is NOT `paypal.com` (Domain Mismatch), the score drops significantly -> **Phishing**.
        - If the site looks like PayPal and IS `paypal.com`, the score remains high -> **Legitimate**.
        - If the site does NOT look like PayPal (Low DOM Similarity), it is flagged as **Phishing** (in the context of "This is not the PayPal login page you are looking for").

## 3. Key Files & Components

### Backend (`app.py`)
The central controller.
- **`predict()`**: Orchestrates the entire flow.
- **`get_url_score()`**: Loads the Keras model and predicts based on URL features.
- **`get_dom_score()`**: Calls the Puppeteer script and computes similarity.
- **`fuse_scores()`**: Implements the logic to combine scores and determine the final label ("Phishing" vs "Legitimate").

### DOM Analyzer (`dom_analyzer/`)
- **`puppeteer_script.js`**: A Node.js script that:
    - Launches a headless Chrome browser.
    - Navigates to a URL.
    - Traverses the DOM to build a simplified JSON tree (Tag Name + Children).
    - Saves the tree to a file for Python to read.
- **`dom_similarity.py`**: Calculates the similarity score between two JSON DOM trees.
- **`tree_edit_distance.py`**: Implements the algorithm to count how many edits (inserts/deletes) are needed to turn one tree into the other.

### Frontend (`static/`)
- **`index.html`**: The user interface.
- **`script.js`**: Handles the form submission and displays the progress bars for URL Score, DOM Score, and Final Result.
