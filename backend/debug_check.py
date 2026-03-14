import sys
sys.path.insert(0, '.')
from url_analyzer import analyze_url
import model as ml_model

url = "http://paypal-secure-login.tk/verify/account?update=true"
try:
    analysis = analyze_url(url)
    print("analyze_url OK")
    print("heuristic_score:", analysis["heuristic_score"])
    print("features:", list(analysis["features"].keys())[:5])
    
    pred = ml_model.predict(analysis["features"], analysis["heuristic_score"])
    print("predict OK:", pred)
except Exception as e:
    import traceback
    traceback.print_exc()
