from flask import render_template, request, jsonify, current_app
from flask_login import login_required
import requests
import ipaddress
from socket import getaddrinfo, AF_INET, AF_INET6
from . import bp 

# --- SSRF Mitigation Helper Functions ---

def is_private_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback or ip_obj.is_unspecified
    except ValueError:
        return False

def resolve_and_check_ip(url):
    try:
        hostname = requests.utils.urlparse(url).netloc
        if not hostname: return False
        for family, _, _, _, sockaddr in getaddrinfo(hostname, 80, family=0, type=0, proto=0, flags=0):
            if family in (AF_INET, AF_INET6):
                ip_address = sockaddr[0]
                if is_private_ip(ip_address):
                    return True
        return False
    except Exception:
        return False

# --- Blueprint Routes ---

@bp.route('/')
@login_required # Added security
def index(): # Simplified name
    return render_template('redirect_checker_index.html') # Updated template name


@bp.route('/trace', methods=['POST'])
@login_required # Added security
def trace_redirects_api():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Invalid request format. JSON payload expected.'}), 400

    url_to_trace = data.get('url', '').strip()

    if not url_to_trace:
        return jsonify({'error': 'URL is required.'}), 400

    # SSRF Check
    if not url_to_trace.startswith('http://') and not url_to_trace.startswith('https://'):
        url_to_trace = 'http://' + url_to_trace
    
    if resolve_and_check_ip(url_to_trace):
        return jsonify({'error': 'SSRF Blocked: This host resolves to a restricted IP.'}), 403

    redirect_history = []
    final_url = url_to_trace 
    final_status_code = None
    error_message = None 
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 RedirectCheckerBot/1.0'
    }
    
    try:
        response = requests.get(url_to_trace, headers=headers, timeout=15, allow_redirects=True, verify=True)
        final_url = response.url 
        final_status_code = response.status_code 

        if response.history:
            for i, resp_history_item in enumerate(response.history):
                redirect_history.append({
                    'hop': i + 1,
                    'status_code': resp_history_item.status_code,
                    'url': resp_history_item.url,
                    'location_header': resp_history_item.headers.get('Location', 'N/A')
                })
        
        redirect_history.append({
            'hop': len(response.history) + 1,
            'status_code': final_status_code,
            'url': final_url,
            'location_header': 'Final Destination'
        })

    except requests.exceptions.TooManyRedirects:
        error_message = "Redirect loop detected."
    except requests.exceptions.RequestException as e:
        error_message = "A network or connection error occurred."
        current_app.logger.warning(f"Redirect error: {e}")
    except Exception as e_gen:
        error_message = "An unexpected server error occurred."
        current_app.logger.error(f"Redirect generic error: {e_gen}", exc_info=True)

    response_data = {
        'original_url': url_to_trace,
        'final_url': final_url,
        'final_status_code': final_status_code,
        'redirect_history': redirect_history,
    }
    
    if error_message:
        response_data['error_while_tracing'] = error_message # Updated key to match JS expectations

    return jsonify(response_data)