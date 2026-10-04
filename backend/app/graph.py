def build_graph(entities):
    nodes = []
    edges = []
    for i, e in enumerate(entities):
        nodes.append({"id": f"e{i}", "label": e.entity_type, "value": e.text, "confidence": e.confidence})
    for i in range(len(entities)):
        for j in range(i+1, len(entities)):
            distance = abs(entities[i].start - entities[j].start)
            if distance <= 220:
                edges.append({"source": f"e{i}", "target": f"e{j}", "weight": round(max(0.1, 1-distance/220), 3)})
    return {"nodes": nodes, "edges": edges}
