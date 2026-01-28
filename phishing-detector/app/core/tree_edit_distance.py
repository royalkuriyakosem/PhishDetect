def tree_edit_distance(t1, t2):
    if t1["tag"] != t2["tag"]:
        cost = 1
    else:
        cost = 0
    c1 = t1.get("children", [])
    c2 = t2.get("children", [])
    total = abs(len(c1) - len(c2))
    for child1, child2 in zip(c1, c2):
        total += tree_edit_distance(child1, child2)
    return cost + total