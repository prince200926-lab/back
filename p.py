import requests

try:
    r = requests.get("https://identitytoolkit.googleapis.com")
    print("Connection successful:", r.status_code)
except Exception as e:
    print("Connection failed:", e)
