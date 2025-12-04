import json
from dom_similarity import dom_score

brands = ['paypal', 'facebook', 'amazon']
for brand in brands:
    real_path = f"brands/{brand}_dom.json"
    fake_path = f"phishing/fake_{brand}_dom.json"
    
    real_score = dom_score(real_path, real_path)
    fake_score = dom_score(fake_path, real_path)
    
    print(f"{brand.capitalize()} Real Score: {real_score:.3f} | Fake Score: {fake_score:.3f}")
    
    # Save scores
    with open(f"phishing/{brand}_scores.json", "w") as f:
        json.dump({"real": real_score, "fake": fake_score}, f)