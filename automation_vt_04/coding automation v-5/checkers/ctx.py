import requests
from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv("CTX_API_KEY")

IOC_TYPE_PATHS = {
    "hash": "file",
    "ip": "ip",
    "domain": "domain"
}

# --- PERBAIKAN 1: Urutan argumen diubah ---
# Sekarang sesuai dengan panggilan fungsi di app.py
def check_ctx(ioc_value, ioc_type):
    
    path_segment = IOC_TYPE_PATHS.get(ioc_type)
    
    if not path_segment:
        # Error "Invalid IoC Type" terjadi di sini karena argumen terbalik
        print(f"Error CTX: Tipe IoC tidak dikenal: {ioc_type}")
        return "Error: Invalid IoC Type"
    
    url = f"https://api.ctx.io/v1/{path_segment}/report/{ioc_value}"
    headers = {"x-api-key": API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 404:
            return "Not Found"
            
        response.raise_for_status() # Menangani error 401, 500, dll.
        data = response.json()
        
        # --- PERBAIKAN 2: Logika parsing yang benar ---
        # 1. Dapatkan blok data yang relevan
        analysis_data = data.get("ctx_data") or \
                        data.get("ip_data") or \
                        data.get("domain_data") or \
                        {} # Default ke dict kosong

        # 2. Dapatkan nama deteksi DARI BLOK tersebut
        detect_name = analysis_data.get("detect")
        
        # --- PERBAIKAN 3: Format return string ---
        # Mengembalikan nilai yang didapat (misal: "malicious" atau "clean")
        # Jika 'detect' tidak ditemukan, ini akan mengembalikan None
        return detect_name 

    except requests.exceptions.RequestException as e:
        print(f"Error saat menghubungi CTX API: {e}")
        return "Error"
    except Exception as e:
        # Menangani error jika respons bukan JSON, dll.
        print(f"Error pemrosesan data CTX: {e}")
        return "Error"