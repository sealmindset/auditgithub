import requests
import psycopg2
import os
import time

def verify_ask_ai():
    db_host = os.getenv("POSTGRES_HOST", "localhost")
    api_url = os.getenv("API_BASE", "http://localhost:8000") + "/ai/analyze-finding"
    
    print(f"Connecting to database at {db_host}...")
    try:
        conn = psycopg2.connect(
            host=db_host,
            database="auditgh_kb",
            user="auditgh",
            password="auditgh_secret",
            port="5432"
        )
        cur = conn.cursor()
        cur.execute("SELECT id FROM findings LIMIT 1;")
        result = cur.fetchone()
        conn.close()
        
        if not result:
            print("No findings found in database. Cannot verify.")
            return

        finding_id = result[0]
        print(f"Testing with finding ID: {finding_id}")

        # Call API
        print(f"Calling {api_url}...")
        response = requests.post(api_url, json={"finding_id": str(finding_id)})

        print(f"Status Code: {response.status_code}")
        if response.status_code == 200:
            print("Success!")
            print(f"Analysis length: {len(response.json().get('analysis', ''))}")
            print("Preview:", response.json().get('analysis', '')[:100])
        else:
            print("Failed!")
            print(response.text)

    except Exception as e:
        print(f"Verification failed: {e}")

if __name__ == "__main__":
    # Wait for services to be up
    print("Waiting 10s for services...")
    time.sleep(10)
    verify_ask_ai()
