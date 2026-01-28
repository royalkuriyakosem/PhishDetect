import json
import numpy as np
from .tree_edit_distance import tree_edit_distance
def load_dom(path):
    with open(path, "r") as f:
        data = json.load(f)
        return data.get("dom", data) # Handle both new and old formats
def dom_score(test_dom_path, brand_dom_path):
    test = load_dom(test_dom_path)
    brand = load_dom(brand_dom_path)
    dist = tree_edit_distance(test, brand)
    score = np.exp(-dist / 100)  # Tune /100 if needed
    return float(score)