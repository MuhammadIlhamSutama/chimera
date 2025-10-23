from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from webdriver_manager.chrome import ChromeDriverManager

# --- PERUBAHAN DI SINI ---
# 1. Buat pemetaan tipe ke path URL IBM
IOC_TYPE_PATHS_IBM = {
    "hash": "malware",
    "ip": "ip",
    "domain": "url"  # IBM X-Force menggunakan /url/ untuk domain
}
# --- AKHIR PERUBAHAN ---

# --- PERUBAHAN DI SINI ---
# 2. Ubah argumen fungsi
def check_ibm_xforce(ioc_value, ioc_type):
# --- AKHIR PERUBAHAN ---

    # 3. Dapatkan path URL yang benar
    path_segment = IOC_TYPE_PATHS_IBM.get(ioc_type)
    if not path_segment:
        print(f"Error IBM: Tipe IoC tidak dikenal: {ioc_type}")
        return "Error: Invalid IoC Type"

    # 4. Bangun URL secara dinamis
    url = f"https://exchange.xforce.ibmcloud.com/{path_segment}/{ioc_value}"
    
    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument('log-level=3')
    driver = None
    try:
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.get(url)
        wait = WebDriverWait(driver, 15)
        
        # Logika scraping Anda saat ini (span.scorebackgroundfilter.numtitle)
        # kebetulan berfungsi untuk halaman IP dan URL juga.
        elem = wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "span.scorebackgroundfilter.numtitle"))
        )
        # Mengambil teks (misalnya "7 / 10")
        score_text = elem.text.strip()
        
        # Opsi: Anda bisa mengembalikan "7/10" atau hanya "7"
        # return score_text.split('/')[0].strip() # Untuk "7"
        return score_text # Untuk "7 / 10"

    except (TimeoutException, NoSuchElementException):
        # Ini bisa berarti "Not Found" atau halaman gagal dimuat
        return "Not Found"
    except Exception as e:
        print(f"Error Selenium IBM: {e}")
        return "Error"
    finally:
        if driver:
            driver.quit()