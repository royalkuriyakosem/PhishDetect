# Development Log & Troubleshooting

This document tracks significant issues encountered during development, their root causes, and resolutions. It serves as a history of major modifications and fixes.

## [2025-12-07] Visual Similarity Engine Implementation

### Feature
Implemented a **Visual Similarity Engine** to detect phishing sites that visually mimic legitimate brands, even if the underlying DOM structure is slightly different.

### Implementation Details
- **Puppeteer**: Updated to capture full-page screenshots of both the suspect URL and the brand URL.
- **Image Processing**: Created `dom_analyzer/visual_similarity.py` using **SSIM (Structural Similarity Index)** from `scikit-image` to compare the screenshots.
- **Backend**: Integrated the visual score into `app.py`. The final fusion logic now weighs:
    - URL Score: 10%
    - DOM Score: 45%
    - Visual Score: 45%
- **Frontend**: Added a "Visual Score" progress bar to the results card.

### Dependencies Added
- `scikit-image`
- `opencv-python`

---

## [2025-12-07] Puppeteer Subprocess Timeout

### Issue
The DOM analysis phase was failing with a `subprocess.TimeoutExpired` error after 60 seconds. The Puppeteer script was hanging indefinitely on certain websites (e.g., Facebook).

### Root Cause
The Puppeteer script was using `waitUntil: "networkidle2"`. This setting waits until there are no more than 2 network connections for at least 500ms. Modern, dynamic websites (especially those with ads, tracking, or live chat) often never reach this state, causing the script to wait until the hard timeout.

### Resolution
Changed the navigation wait condition to `waitUntil: "domcontentloaded"`.
- **Why**: We only need the HTML structure (DOM) to be parsed to perform our analysis. We do not need to wait for all external resources (images, analytics scripts) to finish loading.
- **Result**: Page loads are now significantly faster and reliable, preventing the subprocess timeout.

### Files Modified
- `dom_analyzer/puppeteer_script.js`: Changed `goto` options.
- `app.py`: Cleaned up `subprocess.run` arguments for better reliability.

---

## [2025-12-07] Missing Chrome Binary

### Issue
The Puppeteer subprocess was failing silently or exiting immediately, causing the application to fall back to the "Temp file not created" error.

### Root Cause
The local Chromium binary required by Puppeteer was either missing or corrupted in the cache, likely due to a failed install or environment restriction.

### Resolution
1.  Cleared the Puppeteer cache (`rm -rf ~/.cache/puppeteer`).
2.  Manually reinstalled the browser binary using the local package: `./node_modules/.bin/puppeteer browsers install chrome`.

### Files Modified
- None (Environment fix).
