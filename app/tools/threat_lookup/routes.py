from flask import render_template, request, jsonify, current_app
from flask_login import login_required
import requests
import hashlib
import json
import socket
import dns.resolver
import dns.exception
import dns.reversename
import whois
import traceback
import time
from urllib.parse import urlparse
import base64

from . import bp 

# --- API URL Constants ---
VT_API_URL_FILE_REPORT = "https://www.virustotal.com/api/v3/files/" 
VT_API_URL_URL_REPORT = "https://www.virustotal.com/api/v3/urls/" 
VT_API_URL_IP_REPORT = "https://www.virustotal.com/api/v3/ip_addresses/" 
VT_API_URL_DOMAIN_REPORT = "https://www.virustotal.com/api/v3/domains/" 


# --- Helper Functions ---
def calculate_hashes_from_stream(file_stream):
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    chunk_size = 8192
    
    if hasattr(file_stream, 'seek'): file_stream.seek(0)
    while True:
        chunk = file_stream.read(chunk_size)
        if not chunk: break
        md5_hash.update(chunk)
        sha1_hash.update(chunk)
        sha256_hash.update(chunk)
    if hasattr(file_stream, 'seek'): file_stream.seek(0)
        
    return {'md5': md5_hash.hexdigest(), 'sha1': sha1_hash.hexdigest(), 'sha256': sha256_hash.hexdigest()}

def query_virustotal_api(endpoint_url, resource_id, api_key):
    if not api_key: return {"error": "VirusTotal API key not configured on server."}
    
    url = f"{endpoint_url}{resource_id}"
    headers = { "x-apikey": api_key, "Accept": "application/json" }
    
    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200: return response.json()
        elif response.status_code == 404: return {"error": "Resource not found in VirusTotal."}
        else: return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        return {"error": f"Network error while querying VirusTotal: {e}"}

def get_url_id_for_vt(url_to_scan: str) -> str | None:
    try:
        url_bytes = url_to_scan.encode('utf-8')
        b64_encoded_bytes = base64.urlsafe_b64encode(url_bytes)
        return b64_encoded_bytes.decode('utf-8').rstrip('=')
    except Exception: return None

def get_ip_info(ip_address, vt_api_key, abuse_api_key):
    results = {"ip": ip_address, "ptr_records": [], "whois": "N/A", "abuseipdb": "N/A", "virustotal": "N/A"}
    try:
        addr = dns.reversename.from_address(ip_address)
        results["ptr_records"] = [str(rdata.target) for rdata in dns.resolver.resolve(addr, 'PTR')]
    except Exception: results["ptr_records"] = ["No PTR record found"]
    
    try:
        w_obj = whois.whois(ip_address)
        results["whois"] = {k: v for k, v in w_obj.items() if v} if w_obj else "Not found."
    except Exception: results["whois"] = "WHOIS lookup failed."
    
    results["virustotal"] = query_virustotal_api(VT_API_URL_IP_REPORT, ip_address, vt_api_key)
    
    if abuse_api_key:
        try:
            response = requests.get('https://api.abuseipdb.com/api/v2/check', 
                                    params={'ipAddress': ip_address, 'maxAgeInDays': '90'}, 
                                    headers={'Accept': 'application/json', 'Key': abuse_api_key}, timeout=10)
            results["abuseipdb"] = response.json().get('data', {}) if response.status_code == 200 else {"error": f"API Error {response.status_code}"}
        except Exception: results["abuseipdb"] = {"error": "Query failed"}
    return results

def get_domain_info(domain, vt_api_key):
    results = {"domain": domain, "dns_records": {}, "whois": "N/A", "virustotal": "N/A"}
    for r_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, r_type)
            results["dns_records"][r_type] = [str(rdata) for rdata in answers]
        except Exception: results["dns_records"][r_type] = ["Not found"]
    try:
        w_obj = whois.whois(domain)
        results["whois"] = {k: v for k, v in w_obj.items() if v} if w_obj else "Not found."
    except Exception: results["whois"] = "WHOIS lookup failed."
    results["virustotal"] = query_virustotal_api(VT_API_URL_DOMAIN_REPORT, domain, vt_api_key)
    return results

def get_url_info(url_to_scan, vt_api_key):
    results = {"url": url_to_scan, "virustotal": "N/A", "urlhaus": "N/A"}
    url_id = get_url_id_for_vt(url_to_scan)
    results["virustotal"] = query_virustotal_api(VT_API_URL_URL_REPORT, url_id, vt_api_key) if url_id else {"error": "Invalid URL ID"}
    try:
        response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={'url': url_to_scan}, timeout=10)
        results["urlhaus"] = response.json() if response.status_code == 200 else {"error": "API Error"}
    except Exception: results["urlhaus"] = {"error": "Query failed"}
    return results

# --- Blueprint Routes ---

@bp.route('/')
@login_required # Added security
def index(): # Simplified name
    # [FIX] Updated template name
    return render_template('index_lookup.html')

@bp.route('/lookup', methods=['POST'])
@login_required # Added security
def lookup_api():
    VT_API_KEY = current_app.config.get('VIRUSTOTAL_API_KEY')
    ABUSEIPDB_API_KEY = current_app.config.get('ABUSEIPDB_API_KEY')
    
    data = request.form 
    indicator_type = data.get('indicatorType')
    indicator_value = data.get('indicatorValue', '').strip()
    file_storage = request.files.get('indicatorFile')

    if not indicator_type: return jsonify({'error': 'Indicator type required.'}), 400

    results_payload = {} 
    try:
        if indicator_type == 'file_hash':
            if not indicator_value: return jsonify({'error': 'File hash required.'}), 400
            results_payload['virustotal'] = query_virustotal_api(VT_API_URL_FILE_REPORT, indicator_value, VT_API_KEY)
        
        elif indicator_type == 'file_upload':
            if not file_storage: return jsonify({'error': 'File required.'}), 400
            hashes = calculate_hashes_from_stream(file_storage.stream)
            results_payload['calculated_hashes'] = hashes
            results_payload['virustotal'] = query_virustotal_api(VT_API_URL_FILE_REPORT, hashes['sha256'], VT_API_KEY)
        
        elif indicator_type == 'url':
            if not indicator_value: return jsonify({'error': 'URL required.'}), 400
            if not (indicator_value.startswith('http://') or indicator_value.startswith('https://')):
                indicator_value = 'http://' + indicator_value
            results_payload.update(get_url_info(indicator_value, VT_API_KEY))
        
        elif indicator_type == 'ip_address':
            if not indicator_value: return jsonify({'error': 'IP Address required.'}), 400
            results_payload.update(get_ip_info(indicator_value, VT_API_KEY, ABUSEIPDB_API_KEY))

        elif indicator_type == 'domain':
            if not indicator_value: return jsonify({'error': 'Domain required.'}), 400
            results_payload.update(get_domain_info(indicator_value, VT_API_KEY))
        
        results_payload['type_analyzed'] = indicator_type.replace('_',' ').title()
        results_payload['indicator_value'] = indicator_value if indicator_type != 'file_upload' else (file_storage.filename if file_storage else "N/A")
        
        return jsonify(results_payload)

    except Exception as e:
        current_app.logger.error(f'Threat lookup error: {e}', exc_info=True)
        return jsonify({'error': 'An unexpected server error occurred.'}), 500