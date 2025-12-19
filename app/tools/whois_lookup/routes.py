from flask import render_template, request, jsonify
from flask_login import login_required
import whois
from . import bp

@bp.route('/')
@login_required
def index():
    return render_template('index_whois.html')

@bp.route('/query', methods=['POST'])
@login_required
def query_domain():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        # Perform the WHOIS lookup
        w = whois.whois(domain)
        
        # Convert the Whois object to a dictionary
        # We handle datetime objects by converting them to strings
        result = {}
        for key, value in w.items():
            if value:
                result[key] = str(value)
                
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500