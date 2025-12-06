import json
import numpy as np
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'dom_analyzer'))  # Path fix for dom_similarity

from dom_similarity import dom_score  # From Phase 2

# Tunable weights: URL (fast signal) + DOM (structure check)
URL_WEIGHT = 0.6
DOM_WEIGHT = 0.4

def load_sample_data():
    with open("sample_data.json", "r") as f:
        return json.load(f)

def compute_dom_score(brand, is_fake=False):  # Auto-picks real/fake paths
    brand_dom = f"../dom_analyzer/brands/{brand}_dom.json"
    test_dom = f"../dom_analyzer/phishing/fake_{brand}_dom.json" if is_fake else brand_dom
    return dom_score(test_dom, brand_dom)

def compute_fusion(url_score, dom_score_val):
    hybrid = URL_WEIGHT * url_score + DOM_WEIGHT * dom_score_val
    return float(hybrid)

def get_threshold(brand):
    with open("thresholds.json", "r") as f:
        thresh = json.load(f)
    return thresh.get(brand, 0.5)  # Default

def test_fusion():
    data = load_sample_data()
    results = []
    for item in data:
        # Auto-detect fake for DOM (demo: based on URL keywords)
        is_fake = "fake" in item["url"] or "phish" in item["url"]
        dom_score_val = compute_dom_score(item["brand"], is_fake)
        
        hybrid_score = compute_fusion(item["url_score"], dom_score_val)
        threshold = get_threshold(item["brand"])
        label = "⚠️ PHISHING!" if hybrid_score < threshold else "✅ Legitimate"
        
        results.append({
            "url": item["url"],
            "brand": item["brand"],
            "url_score": item["url_score"],
            "dom_score": dom_score_val,
            "hybrid_score": hybrid_score,
            "threshold": threshold,
            "label": label
        })
        
        print(f"URL: {item['url'][:40]}... | Hybrid: {hybrid_score:.3f} (URL:{item['url_score']:.2f} + DOM:{dom_score_val:.3f}) | {label}")
    
    # Save results
    with open("fusion_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to fusion_results.json")
    return results

if __name__ == "__main__":
    test_fusion()