import vt
import time
import random
from itertools import cycle
from collections import deque
from dotenv import load_dotenv
import os

load_dotenv()

# --- (Semua konfigurasi API_KEYS dan Rate Limiter Anda tetap sama) ---
API_KEYS = [
    os.getenv("VT_API_KEY1"),
    os.getenv("VT_API_KEY2")
]
MAX_REQUESTS_PER_MINUTE_PER_KEY = 4
MAX_RETRIES = 3
key_cycle = cycle(API_KEYS)
api_request_times = {key: deque() for key in API_KEYS}
# --- (Akhir dari bagian yang tidak berubah) ---

# --- PERUBAHAN DI SINI ---
# 1. Buat pemetaan tipe ke VT object path
VT_OBJECT_PATHS = {
    "hash": "files",
    "ip": "ip_addresses",
    "domain": "domains"
}
# --- AKHIR PERUBAHAN ---


# --- PERUBAHAN DI SINI ---
# 2. Ubah argumen fungsi
def check_virustotal(ioc_value, ioc_type):
# --- AKHIR PERUBAHAN ---
    """
    Mendapatkan skor dan family threat dari VirusTotal dengan rate limiter cerdas
    untuk menghindari ban sementara.
    """
    
    # 3. Dapatkan path object VT yang benar
    path_segment = VT_OBJECT_PATHS.get(ioc_type)
    if not path_segment:
        print(f"Error VT: Tipe IoC tidak dikenal: {ioc_type}")
        return "Error: Invalid IoC Type"
        
    # 4. Bangun path object VT secara dinamis
    vt_path = f"/{path_segment}/{ioc_value}"
    
    api_key = next(key_cycle)
    
    # --- (Logika Rate Limiter Anda tetap sama persis) ---
    now = time.time()
    timestamps = api_request_times[api_key]
    while timestamps and now - timestamps[0] > 60:
        timestamps.popleft()
    if len(timestamps) >= MAX_REQUESTS_PER_MINUTE_PER_KEY:
        oldest_timestamp = timestamps[0]
        wait_time = 60 - (now - oldest_timestamp) + 1 
        if wait_time > 0:
            print(f"⏳ VT Rate limit tercapai untuk key {api_key[:4]}... Menunggu {wait_time:.1f} detik.")
            time.sleep(wait_time)
    api_request_times[api_key].append(time.time())
    # --- (Akhir Logika Rate Limiter) ---

    for attempt in range(MAX_RETRIES):
        try:
            with vt.Client(api_key) as client:
                try:
                    # --- PERUBAHAN DI SINI ---
                    # 5. Gunakan vt_path yang dinamis
                    obj = client.get_object(vt_path)
                    # --- AKHIR PERUBAHAN ---
                    
                    # Logika parsing Anda (last_analysis_stats dan popular_threat_classification)
                    # berfungsi dengan baik untuk objek File, IP, dan Domain.
                    stats = obj.last_analysis_stats
                    malicious = stats.get('malicious', 0)
                    
                    # Total verdicts sedikit berbeda antar tipe objek
                    # Pendekatan yang lebih aman adalah menjumlahkan semua
                    total_verdicts = sum(stats.values())
                    
                    if total_verdicts == 0:
                        score_str = "0/0" # Belum dianalisis
                    else:
                        score_str = f"{malicious}/{total_verdicts}"
                    
                    threat_label = ""
                    if hasattr(obj, 'popular_threat_classification'):
                        label_info = obj.popular_threat_classification
                        if label_info and label_info.get('suggested_threat_label'):
                                threat_label = label_info.get('suggested_threat_label')
                    
                    return f"{score_str} {threat_label}".strip()

                except vt.error.APIError as e:
                    if "NotFoundError" in str(e): return "Not Found"
                    if "NotAllowedError" in str(e):
                        print(f"🚨 Terkena ban sementara pada key {api_key[:4]}... Tidur 65 detik.")
                        time.sleep(65)
                        continue
                    else:
                        raise e
                        
        except Exception as e:
            err_msg = str(e)
            if "QuotaExceededError" in err_msg:
                print(f"⚠️ VT Quota harian habis untuk key {api_key[:4]}... Coba kunci lain...")
                try:
                    api_key = next(key_cycle)
                    api_request_times.setdefault(api_key, deque())
                    continue
                except StopIteration:
                    return "Error: Quota semua key habis"
            
            if attempt < MAX_RETRIES - 1:
                sleep_time = 2 ** attempt + random.uniform(0.5, 1.5)
                print(f"⏳ Gagal, mencoba lagi dalam {sleep_time:.1f} detik...")
                time.sleep(sleep_time)
            else:
                return f"Error: {err_msg[:60]}"
    return "Error: Max retries exceeded"