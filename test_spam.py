import openpyxl
import requests
import time

API_URL = "http://localhost:8000"

def main():
    print("Reading malicious_phish.xlsx...")
    wb = openpyxl.load_workbook("malicious_phish.xlsx")
    sheet = wb.active
    
    links = []
    
    # Check headers
    # Row 1 is header (url, type)
    # Let's take 20 URLs. Since it might include benign and phishing, let's take mixing of them.
    for row in sheet.iter_rows(min_row=2, max_row=21, values_only=True):
        url = row[0]
        type_ = row[1]
        links.append((url, type_))
        
    print(f"Loaded {len(links)} links. Generating API Key...")
    
    sess = requests.Session()
    res = sess.post(f"{API_URL}/api/keys/generate")
    if res.status_code != 200:
        print("Failed to generate API key:", res.text)
        return
    api_key = res.json()["api_key"]
    
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    
    success = 0
    total = len(links)
    
    for url, expected_type in links:
        print(f"\n[{expected_type.upper()}] Testing URL: {url}")
        
        url_to_send = url
        if not url.startswith("http://") and not url.startswith("https://"):
            url_to_send = "http://" + url
            
        try:
            res = sess.post(f"{API_URL}/api/check-url", headers=headers, json={"url": url_to_send})
            if res.status_code == 200:
                data = res.json()
                score = data.get("risk_score")
                label = data.get("label")
                print(f"Result: Score {score}, Label: {label.upper()}")
                
                is_malicious = expected_type.lower() != 'benign'
                is_detected = label.lower() == 'phishing'
                
                if is_malicious == is_detected:
                    success += 1
                    print("✅ Correctly identified!")
                else:
                    print("❌ Incorrect identification.")
            else:
                print("Error:", res.status_code, res.text)
                total -= 1
                
        except Exception as e:
            print("Request failed:", e)
            total -= 1
            
        time.sleep(1) # Be nice to our local server
            
    print(f"\nDone! Expected matches: {success} out of {total} successful requests.")

if __name__ == "__main__":
    main()
