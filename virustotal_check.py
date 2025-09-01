import requests, time

API_KEY = "1189d819b7de942c6c0e95b4d952a058528ad4bfb47b219066a7e534174ee49f"
url = "http://cbit.ac.in"

# Step 1: Submit the URL
api_url = "https://www.virustotal.com/api/v3/urls"
headers = {"x-apikey": API_KEY}
data = {"url": url}

response = requests.post(api_url, data=data, headers=headers)

if response.status_code == 200:
    url_id = response.json()["data"]["id"]
    print(f"✅ URL submitted: {url}")
    print(f"URL ID: {url_id}")
    
    # Step 2: Poll until analysis is ready
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
    
    while True:
        result = requests.get(analysis_url, headers=headers).json()
        status = result["data"]["attributes"]["status"]
        
        if status == "completed":
            stats = result["data"]["attributes"]["stats"]
            print("\n📊 Final Scan Results:", stats)
            
            if stats["malicious"] > 0:
                print(f"⚠️ {url} is flagged as malicious/phishing!")
            else:
                print(f"✅ {url} seems safe.")
            break
        else:
            print("⏳ Scan in progress... waiting 10s")
            time.sleep(10)
else:
    print("❌ Error:", response.json())
