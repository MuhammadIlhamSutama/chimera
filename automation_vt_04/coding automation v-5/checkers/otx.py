import requests

# Dictionary untuk memetakan tipe IoC ke segmen path OTX API
IOC_TYPE_PATHS_OTX = {
    "hash": "file",
    "ip": "IPv4",
    "domain": "domain"
}

def check_otx(ioc_value, ioc_type):
    """
    Memeriksa IoC di OTX AlienVault.
    Mengembalikan string tunggal yang diformat jika ditemukan, 
    atau "none" jika tidak.
    """
    path_segment = IOC_TYPE_PATHS_OTX.get(ioc_type)
    
    if not path_segment:
        print(f"Error OTX: Tipe IoC tidak dikenal: {ioc_type}")
        return "Error: Invalid IoC Type"

    # Tentukan ENDPOINT dan URL
    if path_segment == "file":
        endpoint = "analysis"
        url = f"https://otx.alienvault.com/api/v1/indicators/{path_segment}/{ioc_value}/{endpoint}"
    
    elif path_segment == "IPv4" or path_segment == "domain":
        endpoint = "general"
        url = f"https://otx.alienvault.com/api/v1/indicators/{path_segment}/{ioc_value}/{endpoint}"
        
    else:
        return "Error: Unknown Path Segment"

    try:
        r = requests.get(url, timeout=10)
        
        # Jika tidak ditemukan (404), kembalikan "none"
        if r.status_code == 404:
            return "none"
            
        # Tangani error HTTP lainnya
        r.raise_for_status() 
        
        data = r.json()
        
        # --- Ekstrak Data ---
        pulses = 0
        asn = "N/A"

        if endpoint == "general": # IP dan Domain
            pulses = data.get("pulse_info", {}).get("count", 0)
            asn = data.get("asn", "N/A")
        
        elif endpoint == "analysis": # Hash
            pulses = data.get("general", {}).get("pulse_info", {}).get("count", 0)

        # --- LOGIKA BARU: Buat String Hasil ---
        
        # Buat list kosong untuk menampung bagian string
        result_parts = []
        
        # 1. Tambahkan jumlah pulse jika ada
        if pulses > 0:
            result_parts.append(f"{pulses} pulses")
        
        # 2. Tambahkan ASN jika ini adalah IP dan ASN ditemukan
        if ioc_type == "ip" and asn != "N/A":
            result_parts.append(asn)
            
        # --- Kembalikan String ---
        if result_parts:
            # Gabungkan semua bagian dengan spasi
            # Hasil: "16 pulses AS4837 china unicom china169 backbone"
            # atau "16 pulses" (jika hash atau domain)
            return " ".join(result_parts)
        else:
            # Jika list kosong (0 pulses dan tidak ada ASN)
            return "none"
            
    except requests.exceptions.HTTPError as e:
        print(f"Error OTX HTTP: {e}")
        return f"Error: HTTP {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        print(f"Error OTX request: {e}")
        return "Error: Request Failed"
    except Exception as e:
        print(f"Error OTX (unknown): {e}")
        return "Error"