# PhishDetect: Innovation Roadmap (1-Year Plan)

Since you have a **team of 4** and **1 year**, you have the resources to build a commercial-grade security product, not just a student project. Here is a roadmap of "Innovations" that would make this project stand out in a research paper or product launch.

---

## 1. The "Zero-Shot" Brand Discovery (High Innovation)
**Current Limitation**: We rely on a hardcoded list of brands (Facebook, Netflix, etc.).
**The Innovation**: **Dynamic Reference Generation**.
*   **How it works**:
    1.  System scans a suspicious site and extracts keywords (e.g., "Welcome to HDFC Bank").
    2.  System queries a Search Engine API (Google/Bing) for "HDFC Bank official site".
    3.  System assumes the **top result** is the legitimate site.
    4.  System dynamically scrapes that top result and compares the suspicious site against it.
*   **Impact**: Your tool now works for **every company in the world** without you ever manually adding them. This is a huge research contribution.

## 2. Computer Vision: Logo Detection (AI/CV)
**Current Limitation**: We compare the whole screenshot. If the layout is slightly different, score drops.
**The Innovation**: **Object Detection (YOLO/Siamese Networks)**.
*   **How it works**:
    1.  Train a YOLOv8 model on logos of top 50 targeted brands.
    2.  Instead of comparing the whole page, the AI specifically looks for the **PayPal Logo**.
    3.  **Logic**: "I see a PayPal logo (99% confidence), but the URL is `pay-pal-secure.com`. This is Phishing."
*   **Impact**: Detects phishing even if the site looks totally different but uses the brand's logo to fool users.

## 3. NLP: Social Engineering Detection (Natural Language Processing)
**Current Limitation**: We look at structure (DOM) and pixels (Visual). We ignore *meaning*.
**The Innovation**: **Psychological Trigger Analysis**.
*   **How it works**:
    1.  Extract all text from the page.
    2.  Use a Transformer model (BERT/DistilBERT) to analyze the **Tone**.
    3.  Detect triggers: **Urgency** ("Account suspended in 24h!"), **Fear** ("Legal action"), or **Greed** ("You won a prize!").
*   **Impact**: You detect the *intent* of the attacker, not just the technical setup.

## 4. Explainable AI (XAI) & Reporting
**Current Limitation**: We give a score (0.95).
**The Innovation**: **Automated Forensic Report**.
*   **How it works**: Generate a PDF report for the user explaining *why*:
    *   "Detected 'Facebook' logo but domain is registered in Russia."
    *   "Page asks for password but does not use HTTPS."
    *   "Visual similarity is 98% to legitimate Facebook login."
*   **Impact**: Builds trust and educates the user.

---

## Suggested Team Roles (4 Members)

| Member | Role | Focus Area |
| :--- | :--- | :--- |
| **Member 1** | **Core ML & Backend** | Improve the URL Model (Phase 1), build the API, handle the Fusion Logic. |
| **Member 2** | **Computer Vision** | Implement YOLO for Logo Detection, improve Visual Similarity (SSIM/ORB). |
| **Member 3** | **Web Scraper & Dynamic Logic** | Build the "Zero-Shot" Search module, handle Puppeteer, anti-bot evasion. |
| **Member 4** | **Frontend & Extension** | Build the "Cyber" UI, create a **Chrome Extension** (real-world usage). |

---

## What I Can Help You Build NOW
If you want to start on this path, I can help you implement **Innovation #1 (Dynamic Reference)** using a mock search function, or **Innovation #4 (Chrome Extension)** prototype.

Which direction excites your team the most?
