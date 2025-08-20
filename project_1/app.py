import os
import re
import json
import csv
import io
import threading
import time
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, Response
from flask_pymongo import PyMongo
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import requests
from bson import ObjectId

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config["MONGO_URI"] = os.getenv('MONGO_URI', 'mongodb://localhost:27017/cti_dashboard')

mongo = PyMongo(app)
socketio = SocketIO(app, cors_allowed_origins="*")

VT_API_KEY = os.getenv('VT_API_KEY')
ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_KEY')

VT_API_URL = "https://www.virustotal.com/api/v3/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

print(f"VT_API_KEY loaded: {'Yes' if VT_API_KEY else 'No'}")
print(f"ABUSEIPDB_KEY loaded: {'Yes' if ABUSEIPDB_KEY else 'No'}")

def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        return all(0 <= int(octet) <= 255 for octet in ip.split('.'))
    return False

def is_valid_domain(domain):
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}|[a-zA-Z]{2,}\.[a-zA-Z]{2,})$'
    return re.match(pattern, domain) is not None

def calculate_threat_level(vt_data, abuse_data):
    score = 0
    if vt_data and not vt_data.get('error'):
        malicious = vt_data.get('reputation', {}).get('malicious', 0)
        suspicious = vt_data.get('reputation', {}).get('suspicious', 0)
        score += malicious * 10 + suspicious * 5
    if abuse_data and not abuse_data.get('error'):
        confidence = abuse_data.get('abuse_confidence_score', 0)
        score += confidence
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 30:
        return "medium"
    else:
        return "low"

def enrich_ip_virustotal(ip_address):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured", "source": "virustotal"}
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"{VT_API_URL}ip_addresses/{ip_address}", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            return {
                "source": "virustotal",
                "reputation": attributes.get("last_analysis_stats", {}),
                "country": attributes.get("country"),
                "as_owner": attributes.get("as_owner"),
                "network": attributes.get("network"),
                "tags": attributes.get("tags", []),
                "timestamp": datetime.utcnow().isoformat()
            }
        elif response.status_code == 401:
            return {"error": "Invalid API key", "source": "virustotal"}
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded", "source": "virustotal"}
        else:
            return {"error": f"API error: {response.status_code}", "source": "virustotal"}
    except Exception as e:
        return {"error": str(e), "source": "virustotal"}

def check_ip_abuseipdb(ip_address):
    if not ABUSEIPDB_KEY:
        return {"error": "AbuseIPDB API key not configured", "source": "abuseipdb"}
    try:
        headers = {
            'Key': ABUSEIPDB_KEY,
            'Accept': 'application/json',
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return {
                "source": "abuseipdb",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country_code": data.get("countryCode"),
                "usage_type": data.get("usageType"),
                "total_reports": data.get("totalReports", 0),
                "last_reported_at": data.get("lastReportedAt"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "timestamp": datetime.utcnow().isoformat()
            }
        elif response.status_code == 401:
            return {"error": "Invalid API key", "source": "abuseipdb"}
        elif response.status_code == 429:
            return {"error": "Rate limit exceeded", "source": "abuseipdb"}
        else:
            return {"error": f"API error: {response.status_code}", "source": "abuseipdb"}
    except Exception as e:
        return {"error": str(e), "source": "abuseipdb"}

def enrich_domain_virustotal(domain):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured", "source": "virustotal"}
    try:
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(f"{VT_API_URL}domains/{domain}", headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            return {
                "source": "virustotal",
                "reputation": attributes.get("last_analysis_stats", {}),
                "categories": attributes.get("categories", {}),
                "creation_date": attributes.get("creation_date"),
                "last_modification_date": attributes.get("last_modification_date"),
                "tags": attributes.get("tags", []),
                "timestamp": datetime.utcnow().isoformat()
            }
        elif response.status_code == 401:
            return {"error": "Invalid API key", "source": "virustotal"}
        else:
            return {"error": f"API error: {response.status_code}", "source": "virustotal"}
    except Exception as e:
        return {"error": str(e), "source": "virustotal"}

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/lookup', methods=['POST'])
def lookup_indicator():
    try:
        indicator = request.json.get('indicator', '').strip()
        if not indicator:
            return jsonify({"error": "No indicator provided"}), 400
        if is_valid_ip(indicator):
            indicator_type = "ip"
        elif is_valid_domain(indicator):
            indicator_type = "domain"
        else:
            return jsonify({"error": "Invalid indicator format"}), 400

        cached_result = mongo.db.indicators.find_one({
            "indicator": indicator,
            "timestamp": {"$gte": (datetime.utcnow() - timedelta(hours=24)).isoformat()}
        })

        if cached_result:
            cached_result.pop('_id', None)
            cached_result['cached'] = True
            return jsonify(cached_result)

        enrichments = []
        if indicator_type == "ip":
            vt_result = enrich_ip_virustotal(indicator)
            abuse_result = check_ip_abuseipdb(indicator)
            enrichments = [vt_result, abuse_result]
        else:
            vt_result = enrich_domain_virustotal(indicator)
            enrichments = [vt_result]

        threat_level = calculate_threat_level(
            vt_result if 'vt_result' in locals() else None,
            abuse_result if 'abuse_result' in locals() else None
        )

        indicator_doc = {
            "indicator": indicator,
            "type": indicator_type,
            "threat_level": threat_level,
            "sources": [e["source"] for e in enrichments if "source" in e],
            "enrichments": enrichments,
            "tags": [],
            "timestamp": datetime.utcnow().isoformat(),
            "cached": False
        }

        mongo.db.indicators.insert_one(indicator_doc.copy())
        indicator_doc.pop('_id', None)

        try:
            socketio.emit('new_threat', {
                'indicator': indicator,
                'threat_level': threat_level,
                'type': indicator_type
            })
        except:
            pass

        return jsonify(indicator_doc)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/threat_stats')
def threat_stats():
    try:
        pipeline = [
            {"$group": {
                "_id": "$threat_level",
                "count": {"$sum": 1}
            }}
        ]
        result = list(mongo.db.indicators.aggregate(pipeline))
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for item in result:
            if item["_id"] in stats:
                stats[item["_id"]] = item["count"]

        total = sum(stats.values())
        recent_count = mongo.db.indicators.count_documents({
            "timestamp": {"$gte": (datetime.utcnow() - timedelta(hours=24)).isoformat()}
        })

        return jsonify({
            "total": total,
            "recent": recent_count,
            "by_level": stats
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/threat_trends')
def threat_trends():
    try:
        start_date = datetime.utcnow() - timedelta(days=7)
        pipeline = [
            {"$match": {
                "timestamp": {"$gte": start_date.isoformat()}
            }},
            {"$addFields": {
                "date": {"$substr": ["$timestamp", 0, 10]}
            }},
            {"$group": {
                "_id": {
                    "date": "$date",
                    "threat_level": "$threat_level"
                },
                "count": {"$sum": 1}
            }},
            {"$sort": {"_id.date": 1}}
        ]
        result = list(mongo.db.indicators.aggregate(pipeline))
        dates = []
        trends = {"critical": [], "high": [], "medium": [], "low": []}

        for i in range(7):
            date = (start_date + timedelta(days=i)).strftime("%Y-%m-%d")
            dates.append(date)
            date_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for item in result:
                if item["_id"]["date"] == date:
                    level = item["_id"]["threat_level"]
                    if level in date_counts:
                        date_counts[level] = item["count"]
            for level in trends:
                trends[level].append(date_counts[level])

        return jsonify({
            "labels": dates,
            "datasets": [
                {"label": "Critical", "data": trends["critical"], "borderColor": "#e74c3c", "backgroundColor": "rgba(231, 76, 60, 0.1)"},
                {"label": "High", "data": trends["high"], "borderColor": "#f39c12", "backgroundColor": "rgba(243, 156, 18, 0.1)"},
                {"label": "Medium", "data": trends["medium"], "borderColor": "#f1c40f", "backgroundColor": "rgba(241, 196, 15, 0.1)"},
                {"label": "Low", "data": trends["low"], "borderColor": "#27ae60", "backgroundColor": "rgba(39, 174, 96, 0.1)"}
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/recent_threats')
def recent_threats():
    try:
        limit = request.args.get('limit', 10, type=int)
        threats = list(mongo.db.indicators.find({}, {"_id": 0, "indicator": 1, "type": 1, "threat_level": 1, "timestamp": 1, "sources": 1}).sort("timestamp", -1).limit(limit))
        return jsonify(threats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# NEW EXPORT ROUTE
@app.route('/export')
def export_data():
    """Export threat data as CSV or JSON"""
    try:
        # Get query parameters
        format_type = request.args.get('format', 'csv').lower()
        threat_level = request.args.get('level')
        limit = request.args.get('limit', type=int)
        
        # Build query
        query = {}
        if threat_level:
            query['threat_level'] = threat_level
        
        # Fetch data
        cursor = mongo.db.indicators.find(query, {"_id": 0})
        if limit:
            cursor = cursor.limit(limit)
        
        indicators = list(cursor.sort("timestamp", -1))
        
        if not indicators:
            return jsonify({"error": "No data available for export"}), 404
        
        # Generate filename with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        
        if format_type == 'json':
            filename = f"threats_{timestamp}.json"
            return Response(
                json.dumps(indicators, indent=2, default=str),
                mimetype='application/json',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}',
                    'Content-Type': 'application/json'
                }
            )
        
        # CSV export
        filename = f"threats_{timestamp}.csv"
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = ['indicator', 'type', 'threat_level', 'sources', 'tags', 'timestamp', 'country', 'confidence_score']
        writer.writerow(headers)
        
        # Write data rows
        for item in indicators:
            # Extract additional info from enrichments
            country = ""
            confidence_score = ""
            
            for enrichment in item.get('enrichments', []):
                if enrichment.get('source') == 'virustotal':
                    country = enrichment.get('country', '')
                elif enrichment.get('source') == 'abuseipdb':
                    confidence_score = enrichment.get('abuse_confidence_score', '')
            
            row = [
                item.get('indicator', ''),
                item.get('type', ''),
                item.get('threat_level', ''),
                ','.join(item.get('sources', [])),
                ','.join(item.get('tags', [])),
                item.get('timestamp', ''),
                country,
                confidence_score
            ]
            writer.writerow(row)
        
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'text/csv'
            }
        )
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@socketio.on('connect')
def handle_connect():
    print("Client connected")
    emit('status', {'msg': 'Connected to CTI Dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected")

def simulate_threat_feed():
    sample_threats = [
        ("192.168.1.100", "ip"),
        ("malware-site.com", "domain"),
        ("203.45.67.89", "ip"),
        ("phishing-bank.net", "domain"),
        ("185.220.101.45", "ip")
    ]
    while True:
        try:
            indicator, itype = random.choice(sample_threats)
            threat_doc = {
                "indicator": indicator,
                "type": itype,
                "threat_level": random.choice(["low", "medium", "high", "critical"]),
                "sources": ["simulated_feed"],
                "enrichments": [{
                    "source": "simulated_feed",
                    "score": random.randint(1, 100),
                    "timestamp": datetime.utcnow().isoformat()
                }],
                "tags": [random.choice(["malware", "phishing", "botnet", "scanning"])],
                "timestamp": datetime.utcnow().isoformat()
            }
            mongo.db.indicators.insert_one(threat_doc.copy())
            threat_doc.pop('_id', None)
            socketio.emit('new_threat', threat_doc)
            time.sleep(random.randint(30, 120))
        except Exception as e:
            print(f"Error in threat feed simulation: {e}")
            time.sleep(60)

if __name__ == '__main__':
    print("Starting CTI Threat Intelligence Dashboard...")
    with app.app_context():
        try:
            mongo.db.indicators.create_index("indicator")
            mongo.db.indicators.create_index("threat_level")
            mongo.db.indicators.create_index("timestamp")
            print("Database indexes created successfully")
        except Exception as e:
            print(f"Error creating indexes: {e}")
    feed_thread = threading.Thread(target=simulate_threat_feed, daemon=True)
    feed_thread.start()
    print("Background threat simulation started")
    print("Starting Flask-SocketIO server on http://localhost:5000")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
