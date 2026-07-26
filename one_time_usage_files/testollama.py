import requests
import time

def test_local_ollama():
    url = "http://localhost:11434/api/generate"
    
    # We use a simple cybersecurity prompt to test the reasoning
    payload = {
        "model": "phi3",
        "prompt": "Explain what a cybersecurity honeypot is in exactly one sentence.",
        "stream": False
    }
    
    print("Attempting to connect to Ollama at http://localhost:11434...")
    start_time = time.time()
    
    try:
        # 120 second timeout just like we planned for the main app
        response = requests.post(url, json=payload, timeout=120)
        
        if response.status_code == 200:
            elapsed_time = round(time.time() - start_time, 2)
            data = response.json()
            reasoning = data.get("response", "No response text found.")
            
            print("\nConnection Successful.")
            print(f"Time taken: {elapsed_time} seconds")
            print("-" * 40)
            print("Phi3 Output:")
            print(reasoning)
            print("-" * 40)
            
        else:
            print(f"\nConnection failed with HTTP Status Code: {response.status_code}")
            print("Response text: ", response.text)
            
    except requests.exceptions.Timeout:
        print("\nRequest timed out. The model is taking too long to respond.")
        print("Check if your machine has enough RAM/CPU resources available.")
    except requests.exceptions.ConnectionError:
        print("\nConnection refused. Ollama is not running or port 11434 is blocked.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    test_local_ollama()