# 🛡️ CTI Threat Intelligence Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3.0-green.svg)](https://flask.palletsprojects.com/)
[![MongoDB](https://img.shields.io/badge/MongoDB-6.0+-green.svg)](https://www.mongodb.com/)

> A real-time **Cyber Threat Intelligence Dashboard** that aggregates threat feeds from multiple sources, provides interactive visualizations, and enables security analysts to perform threat lookups and analysis.

## ✨ Features

- 🔍 **Real-time threat lookups** for IP addresses, domains, and URLs
- 📊 **Interactive data visualizations** powered by Chart.js
- ⚡ **Live threat feed** with WebSocket updates
- 🔗 **Multi-source enrichment** via VirusTotal and AbuseIPDB APIs
- 💾 **Intelligent caching** with MongoDB storage
- 📤 **Data export** in CSV and JSON formats
- 🎯 **Automated threat classification** with customizable scoring
- 📈 **Historical trend analysis** and statistics

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **MongoDB 4.4+**
- **VirusTotal API Key** ([Get here](https://www.virustotal.com/gui/join-us))
- **AbuseIPDB API Key** ([Get here](https://www.abuseipdb.com/register))

### Installation

### 1. **Clone the repository**
  # git clone https://github.com/yourusername/cti-threat-intelligence-dashboard.git
  # cd cti-threat-intelligence-dashboard

2. **Set up virtual environment**
  python -m venv venv

  **On Windows**
  venv\Scripts\activate

  **On macOS/Linux**
  source venv/bin/activate

3. **Install dependencies**
  pip install -r requirements.txt

4. **Configure environment variables**
  **Copy environment template**
  cp .env.example .env
  **Edit .env with your API keys**

5. **Start MongoDB**
  **On Windows**
  net start MongoDB

**On macOS/Linux**
  sudo systemctl start mongod

6. **Run the application**
  python app.py

7. **Access the dashboard**
  http://localhost:5000

## 🔧 Configuration

### Environment Variables (.env)
**Flask Configuration**
  SECRET_KEY=your_secret_key_here
  FLASK_ENV=development

**Database**
  MONGO_URI=mongodb://localhost:27017/cti_dashboard

**API Keys**
  VT_API_KEY=your_virustotal_api_key_here
  ABUSEIPDB_KEY=your_abuseipdb_api_key_here

**Optional Settings**
  DEBUG=True
  LOG_LEVEL=INFO

## 🔌 API Endpoints

| Endpoint | Method | Description |
|----------|---------|-------------|
| `/` | GET | Dashboard interface |
| `/lookup` | POST | Threat intelligence lookup |
| `/threat_stats` | GET | Current threat statistics |
| `/threat_trends` | GET | Historical trend data |
| `/recent_threats` | GET | Latest threat indicators |
| `/export` | GET | Export data (CSV/JSON) |

### Example Usage
**Lookup threat intelligence for an IP**
  curl -X POST http://localhost:5000/lookup
  -H "Content-Type: application/json"
  -d '{"indicator": "8.8.8.8"}'

**Get threat statistics**
  curl http://localhost:5000/threat_stats

**Export critical threats as CSV**
  curl "http://localhost:5000/export?format=csv&level=critical" > threats.csv

## 🛠️ Technology Stack

- **Backend**: Python, Flask, Flask-SocketIO
- **Frontend**: HTML5, CSS3, JavaScript, Chart.js
- **Database**: MongoDB with intelligent indexing
- **APIs**: VirusTotal, AbuseIPDB
- **Real-time**: WebSocket (Socket.IO)
- **Styling**: Modern dark theme with responsive design

## 🏗️ Architecture


## 📸 How to Use

1. **Open the dashboard** at `http://localhost:5000`
2. **Enter an IP address or domain** in the search field
3. **Click "Analyze"** to perform threat lookup
4. **View results** with threat level, enrichment data, and sources
5. **Monitor live updates** via the real-time threat feed
6. **Export data** using the export controls with filtering options
7. **View analytics** through interactive charts and statistics

## 🔒 Security Features

- **API Key Protection**: Stored securely in environment variables
- **Input Validation**: All user inputs are sanitized and validated
- **Rate Limiting**: Built-in protection against API abuse
- **Caching System**: Reduces external API calls and improves performance
- **Error Handling**: Graceful degradation when external services fail

## 🧪 Testing
**Test the application**
python app.py

**Verify MongoDB connection**
Check if MongoDB is running on port 27017

**Test API endpoints**
curl http://localhost:5000/threat_stats

## 🆘 Troubleshooting

### Common Issues

**MongoDB Connection Error**
- Ensure MongoDB is installed and running
- Check connection string in `.env` file
- Verify MongoDB service status

**API Key Errors (401 Unauthorized)**
- Verify API keys are correctly set in `.env`
- Check VirusTotal and AbuseIPDB account status
- Ensure API keys have proper permissions

**Port 5000 Already in Use**
- Find and terminate processes using port 5000
- Or change port in `app.py` to another value

**Environment Variables Not Loading**
- Ensure `.env` file exists in project root
- Verify python-dotenv is installed
- Check file permissions on `.env`

## 🙏 Acknowledgments

- **VirusTotal** for providing comprehensive malware analysis API
- **AbuseIPDB** for IP reputation and abuse reporting services
- **Chart.js** for beautiful and responsive data visualizations
- **Flask** for the lightweight and flexible web framework
- **MongoDB** for reliable document storage and querying
- **Socket.IO** for real-time web communication
