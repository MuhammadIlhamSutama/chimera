# file: app.py
import asyncio
import sys
import json
import os
import concurrent.futures
from flask import Flask, render_template, request, jsonify

# Import semua fungsi dari folder checkers
from checkers.ctx import check_ctx
from checkers.ibm_xforce import check_ibm_xforce
from checkers.otx import check_otx
from checkers.virustotal import check_virustotal

# Solusi untuk beberapa masalah event loop di Windows
if sys.platform == "win32" and sys.version_info >= (3, 8):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

app = Flask(__name__)


def run_hash_checks(hash_value):
    """Menjalankan semua checker secara paralel dan mengumpulkan hasilnya."""
    checkers = {
        "VirusTotal": check_virustotal,
        "CTX.io": check_ctx,
        "OTX AlienVault": check_otx,
        "IBM X-Force": check_ibm_xforce,
    }
    results = {}
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_map = {executor.submit(func, hash_value): name for name, func in checkers.items()}
        for future in concurrent.futures.as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                print(f"Checker '{name}' menghasilkan error: {exc}")
                results[name] = f"Execution Error"
    return results


def format_results_to_string(results, hash_value, file_name):
    """Mengubah dictionary hasil menjadi string yang terformat sesuai permintaan."""
    file_info_str = f"({file_name})" if file_name else ""
    first_line = f"1. {hash_value}{file_info_str}"
    output_lines = [first_line]
    
    sorted_platforms = ["Cyfirma", "VirusTotal", "IBM X-Force", "OTX AlienVault", "CTX.io"]

    for platform in sorted_platforms:
        result = results.get(platform, "Not Checked")
        line = ""
        
        if platform == "Cyfirma":
            line = f"* Cyfirma ....."
        
        elif platform == "VirusTotal":
            if isinstance(result, dict):
                label = result.get('label', '').replace('.', ' ', 1).capitalize()
                line = f"* Virus Total {result.get('score_str', 'N/A')} {label}".strip()
            else:
                line = f"* Virus Total {result}"

        elif platform == "IBM X-Force":
            risk_level = str(result).lower()
            try:
                score = float(result)
                if score >= 7: risk_level = 'high'
                elif score >= 4: risk_level = 'medium'
                else: risk_level = 'low'
            except (ValueError, TypeError):
                pass
            line = f"* Ibm exchange {risk_level}"

        elif platform == "OTX AlienVault":
            if isinstance(result, dict):
                pulses = result.get('pulses', 0)
                otx_result = "none" if pulses == 0 else f"{pulses} pulses"
                line = f"* Otx alienvault {otx_result}"
            else:
                line = f"* Otx alienvault {str(result).lower()}"

        elif platform == "CTX.io":
            if isinstance(result, dict):
                detect_info = result.get('detect')
                if detect_info: line = f"* CTX {detect_info}"
                else: line = f"* CTX {result.get('status', 'error')}"
            else:
                line = f"* CTX {result}"
        
        if line:
            output_lines.append(line)
            
    # Pisahkan baris pertama dari detail CTI lainnya untuk fleksibilitas
    cti_details = "\n".join(output_lines[1:])
    return f"{first_line}\n{cti_details}"


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/ip')
def ip_page():
    return render_template('index_ip.html')

@app.route('/domain')
def domain_page():
    return render_template('index_domain.html')  


@app.route('/api/templates')
def get_templates():
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        templates_path = os.path.join(script_dir, 'templates.json')
        with open(templates_path, 'r', encoding='utf-8') as f:
            templates = json.load(f)
        return jsonify(templates)
    except FileNotFoundError:
        return jsonify({"error": "templates.json not found"}), 404

@app.route('/api/check', methods=['POST'])
def api_check():
    data = request.json
    ioc_value = data.get('ioc_value')
    ioc_type = data.get('ioc_type')
    file_name = data.get('file_name', '') 

    if not ioc_value or not ioc_type:
        return jsonify({"error": "ioc_value and ioc_type are required"}), 400

   
    vt_result = check_virustotal(ioc_value, ioc_type)
    ibm_result = check_ibm_xforce(ioc_value, ioc_type)
    otx_result = check_otx(ioc_value, ioc_type) 
    ctx_result = check_ctx(ioc_value, ioc_type)   
        
    if ioc_type == 'ip' or ioc_type == 'domain':
        # Ganti titik '.' menjadi '[.]' untuk IP dan domain
        display_ioc = ioc_value.replace('.', '[.]')
    else:
        # Biarkan apa adanya untuk tipe lain (seperti 'hash')
        display_ioc = ioc_value

    # 2. Buat header_line berdasarkan format yang diinginkan
    if file_name and ioc_type == 'hash':
        header_line = f"1. {display_ioc} {file_name}"
    elif ioc_type == 'ip':
        header_line = f"1. {display_ioc} {file_name}"
    else:
        header_line = f"1. *.{display_ioc}"
        
    # 2. Buat daftar hasil
    scan_output_lines = [
        header_line,
        f"* Virus Total {vt_result}",
        f"* Ibm exchange {ibm_result}",
        f"* Otx alienvault {otx_result}",
        f"* CTX {ctx_result}"
    ]
    
    # 3. Gabungkan semua baris dengan karakter newline
    scan_output = "\n".join(scan_output_lines)
    
    # --- AKHIR PERUBAHAN ---

    # Kirim JSON kembali ke frontend
    return jsonify({
        "ioc_value": ioc_value,
        "file_name": file_name,
        "scan_output": scan_output  # Ini adalah string yang sudah diformat
    })


if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)