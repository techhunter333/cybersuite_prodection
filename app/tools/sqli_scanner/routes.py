import requests
from flask import render_template, request, jsonify
from flask_login import login_required
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from . import bp

# Common payloads to test
PAYLOADS = ["'", "\"", "1=1", "' OR '1'='1", "\"; --"]

# Common SQL Error signatures in HTML responses
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlstate"
]

@bp.route('/')
@login_required
def index():
    return render_template('index_sqli.html')

@bp.route('/scan', methods=['POST'])
@login_required
def scan_url():
    target_url = request.json.get('url')
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        target_url = 'http://' + target_url

    results = []
    
    try:
        # 1. Parse URL to find parameters
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)
        
        if not params:
            return jsonify({'error': 'No parameters found in URL to test (e.g., ?id=1).'}), 400

        # 2. Test each parameter
        for param in params:
            for payload in PAYLOADS:
                # Construct malicious URL
                test_params = params.copy()
                test_params[param] = [payload] # Replace value with payload
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                # Send Request
                try:
                    resp = requests.get(test_url, timeout=5)
                    # Check for errors in response
                    for error in SQL_ERRORS:
                        if error in resp.text.lower():
                            results.append({
                                'parameter': param,
                                'payload': payload,
                                'vulnerable': True,
                                'signature': error
                            })
                            break
                except Exception:
                    pass # Ignore timeouts/connection errors for scanning

        return jsonify({'results': results, 'count': len(results)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500