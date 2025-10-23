import requests
import json

r_ip = "60.8.73.174"
url = f"https://api.ctx.io/v1/ip/report/{r_ip}"
headers = {
  "x-api-key": "72F16DC9653940C88419707D21993C2843A62A4BF6F7423B88AAF01DFD3AD93C", # Removed your key for security
}

try:
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()
    data = response.json()
    
    ctx_data_dict = data.get("ctx_data", {})
    value = ctx_data_dict.get("detect")
    status = "malicious" if value == "malicious" else "normal"
    
    print(response.json())
    

except requests.exceptions.HTTPError as http_err:
    print(f"HTTP error occurred: {http_err}")
except requests.exceptions.RequestException as err:
    print(f"An error occurred: {err}")
except json.JSONDecodeError:
    print("Error: Failed to decode JSON response.")
    print("Response text:", response.text)