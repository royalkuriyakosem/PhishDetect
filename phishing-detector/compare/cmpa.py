import json
import sys
import os
import numpy as np

# Add dom_analyzer to path (fix the import error)
dom_path = os.path.join(os.path.dirname(__file__), '..', 'dom_analyzer')  # Relative from compare/ to dom_analyzer/
sys.path.append(dom_path)

from tree_edit_distance import tree_edit_distance  # Now imports correctly

# Paths to the two captured trees
tree1_path = "amazon1_dom.json"
tree2_path = "amazon2_dom.json"

# Load trees
try:
    with open(tree1_path, "r") as f:
        tree1 = json.load(f)
    with open(tree2_path, "r") as f:
        tree2 = json.load(f)
    
    # Compute distance and score
    dist = tree_edit_distance(tree1, tree2)
    score = np.exp(-dist / 25)  # Same param as your dom_score
    
    print(f"Amazon Tree 1 vs Tree 2:")
    print(f"Raw Distance: {dist}")
    print(f"Similarity Score: {score:.3f}")
    print(f"Variation: {'Low (stable)' if dist < 10 else 'High (dynamic changes)'}")
    
    # If score <1.0, baselines need tuning (e.g., /40 in dom_similarity.py)
    
except FileNotFoundError as e:
    print(f"File not found: {e} – Ensure amazon1_dom.json and amazon2_dom.json are in compare/ folder.")
except Exception as e:
    print(f"Error: {e}")