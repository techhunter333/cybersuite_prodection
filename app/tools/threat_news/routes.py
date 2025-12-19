from flask import render_template, request, jsonify, current_app
from flask_login import login_required # Added security
import feedparser
import requests
from datetime import datetime, timezone 
import time 
import traceback 
from concurrent.futures import ThreadPoolExecutor 
from dateutil import parser as date_parser 
import bleach

from . import bp 

# --- Feed Sources (Unchanged) ---
FEED_SOURCES = {
    "CISA Alerts": "https://www.cisa.gov/news/alerts/feed", 
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "NIST NVD (Recent CVEs)": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml", 
    "SecurityWeek": "https://feeds.feedburner.com/securityweek",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/"
}

# --- Helper function to parse feed item dates ---
def parse_feed_date(entry):
    date_obj = None
    if hasattr(entry, 'published_parsed') and entry.published_parsed:
        date_obj = datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
    elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
        date_obj = datetime.fromtimestamp(time.mktime(entry.updated_parsed), tz=timezone.utc)
    elif hasattr(entry, 'published') and entry.published:
        try:
            date_obj = date_parser.parse(entry.published).astimezone(timezone.utc)
        except Exception:
            pass
    return date_obj.isoformat() if date_obj else datetime.now(timezone.utc).isoformat() 

# --- Function to fetch a single feed ---
def fetch_single_feed(feed_name, feed_url):
    # ... (Your existing fetch logic with bleach is perfect) ...
    print(f"Fetching feed: {feed_name} from {feed_url}")
    feed_items = []
    error = None
    headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36' }
    try:
        response = requests.get(feed_url, headers=headers, timeout=15, proxies={'http': '', 'https': ''})
        response.raise_for_status() 
        feed = feedparser.parse(response.content)

        for entry in feed.entries:
            raw_summary = entry.get('summary', entry.get('description', 'No summary available.')).strip()
            clean_summary = bleach.clean(raw_summary, tags=[], strip=True) # Sanitize
            
            feed_items.append({
                'title': entry.get('title', 'No Title'),
                'link': entry.get('link', '#'),
                'published_iso': parse_feed_date(entry),
                'summary': clean_summary[:300] + "..." if len(clean_summary) > 300 else clean_summary,
                'source': feed_name
            })
    except Exception as e:
        error = f"Error fetching {feed_name}: {e}"
        
    return {'name': feed_name, 'items': feed_items, 'error': error}

# --- Routes ---

@bp.route('/')
@login_required # Added security
def index(): # Simplified name
    # [FIX] Updated template name
    return render_template('threat_news_index.html', feed_sources_keys=list(FEED_SOURCES.keys()))

@bp.route('/get-feed', methods=['GET'])
@login_required # Added security
def get_threat_intel_feed_api():
    aggregated_items = []
    feed_errors = []

    with ThreadPoolExecutor(max_workers=len(FEED_SOURCES)) as executor:
        future_to_feed = { executor.submit(fetch_single_feed, name, url): name for name, url in FEED_SOURCES.items() }
        for future in future_to_feed:
            try:
                result = future.result() 
                if result['items']: aggregated_items.extend(result['items'])
                if result['error']: feed_errors.append({'source': result['name'], 'error_message': result['error']})
            except Exception as exc:
                feed_errors.append({'source': future_to_feed[future], 'error_message': str(exc)})
    
    # Sort newest first
    aggregated_items.sort(key=lambda x: x.get('published_iso'), reverse=True)
    
    return jsonify({
        'feed_items': aggregated_items[:100], 
        'errors': feed_errors,
        'total_fetched': len(aggregated_items)
    })