A# Zero-Shot Brand Discovery: Implementation Guide

## Overview
This feature allows PhishDetect to identify **any** brand dynamically by using a Search Engine to find the official website, rather than relying on a hardcoded list.

## External Requirements (What You Need)
To implement this for real, you need access to a **Search Engine API**. I cannot generate this for you; you must sign up for one.
1.  **Google Custom Search JSON API** (Recommended):
    *   **Cost**: Free for 100 queries/day.
    *   **Need**: API Key + Search Engine ID (CX).
    *   **Link**: [Google Developers Console](https://developers.google.com/custom-search/v1/overview)
2.  **Bing Web Search API**:
    *   **Cost**: Free tier available (Azure).
    *   **Need**: API Key.

*If you cannot get an API key right now, I can build a "Mock" version that simulates this behavior for demonstration purposes.*

---

## Implementation Steps

### Step 1: Install Dependencies
We need `requests` to call the Google API.
```bash
pip install requests
```

### Step 2: Create the Search Module
Create a new file `search_engine.py`.
```python
import requests

API_KEY = "YOUR_GOOGLE_API_KEY"
SEARCH_ENGINE_ID = "YOUR_SEARCH_ENGINE_ID"

def get_official_url(query):
    """
    Searches Google for the brand/title and returns the top result.
    Example: query="Login to HDFC Bank" -> returns "https://www.hdfcbank.com/"
    """
    url = f"https://www.googleapis.com/customsearch/v1?key={API_KEY}&cx={SEARCH_ENGINE_ID}&q={query}"
    response = requests.get(url)
    data = response.json()
    
    if "items" in data:
        # Return the first organic result
        return data["items"][0]["link"]
    return None
```

### Step 3: Integrate into `app.py`
Modify the `get_dom_score` function to use this module when the brand is unknown.

**Current Logic:**
```python
if "facebook" in title: brand = "facebook"
else: return None (Fail)
```

**New Zero-Shot Logic:**
```python
if brand_in_list:
    # Use hardcoded logic (Fast)
    pass
else:
    # Zero-Shot Mode (Slower but Powerful)
    print(f"Unknown brand in title: {title}. Searching Google...")
    official_url = get_official_url(title + " official site")
    
    if official_url:
        # Dynamically scrape this new URL
        brand_tree = extract_dom_via_puppeteer(official_url, "temp_dynamic_brand.json")
        # Compare...
```

### Step 4: Handle Performance
**Warning**: Dynamic scraping is slow.
1.  Search API: ~1 second.
2.  Puppeteer Scraping (Official Site): ~5-10 seconds.
**Total Delay**: ~10-15 seconds.
*   **UI Update**: You must update the frontend to show "Searching for official brand..." so the user doesn't think it got stuck.

---

## Dataset Requirements
You do **not** need a training dataset for this. This is an **Unsupervised** approach (it works on live data).
However, for **Evaluation** (to prove it works in your project report), you need:
1.  **Test Set**: 50 Phishing URLs targeting brands *not* in your hardcoded list (e.g., HDFC, SBI, Airbnb, Roblox).
2.  **Metric**: Success Rate (How often did it find the correct official URL?).

## Next Actions
1.  **Decision**: Do you want to try to get a Google API Key now?
2.  **Alternative**: Or should I implement the "Mock" version first (where we pretend to search Google but just return a hardcoded URL for testing)?
