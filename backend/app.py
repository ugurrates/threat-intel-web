"""
Threat Intelligence Web API
Flask backend for ugurrates.github.io/threat-intel
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rate_limiter import (
    init_db, rate_limit, get_from_cache, save_to_cache, 
    cleanup_old_data, get_ip_count_today, DAILY_LIMIT_PER_IP
)

# Import MCP server logic
sys.path.append('/home/claude/threat-intel-mcp')
try:
    from server import analyze_ioc_main
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    print("WARNING: MCP server not found. Using mock data.")

app = Flask(__name__)

# CORS - Allow GitHub Pages domain
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://ugurrates.github.io",
            "http://localhost:*",
            "http://127.0.0.1:*"
        ]
    }
})

# Initialize database
init_db()


@app.route('/')
def index():
    """API info endpoint"""
    return jsonify({
        "service": "Threat Intelligence API",
        "version": "2.2.0",
        "status": "operational",
        "mcp_available": MCP_AVAILABLE,
        "endpoints": {
            "analyze": "/api/analyze (POST)",
            "health": "/api/health (GET)",
            "stats": "/api/stats (GET)"
        },
        "rate_limits": {
            "per_ip_daily": DAILY_LIMIT_PER_IP,
            "global_daily": 100,
            "global_monthly": 500
        },
        "cache_ttl_hours": 24
    })


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "mcp_server": "available" if MCP_AVAILABLE else "unavailable"
    })


@app.route('/api/analyze', methods=['POST'])
@rate_limit
def analyze():
    """
    Analyze IOC endpoint
    
    Request:
        {
            "ioc": "192.0.2.1"
        }
    
    Response:
        {
            "cached": false,
            "ioc": "192.0.2.1",
            "results": {...},
            "rate_limit": {
                "remaining": 4,
                "limit": 5,
                "reset_hours": 12.5
            }
        }
    """
    try:
        data = request.get_json()
        
        if not data or 'ioc' not in data:
            return jsonify({
                "error": "Missing IOC",
                "message": "Request must include 'ioc' field"
            }), 400
        
        ioc = data['ioc'].strip()
        
        if not ioc:
            return jsonify({
                "error": "Empty IOC",
                "message": "IOC cannot be empty"
            }), 400
        
        # Check cache first
        cached_results = get_from_cache(ioc)
        if cached_results:
            results = json.loads(cached_results)
            
            ip = request.remote_addr
            ip_count = get_ip_count_today(ip)
            remaining = max(0, DAILY_LIMIT_PER_IP - ip_count)
            
            return jsonify({
                "cached": True,
                "ioc": ioc,
                "results": results,
                "rate_limit": {
                    "remaining": remaining,
                    "limit": DAILY_LIMIT_PER_IP,
                    "cached_query": True
                }
            })
        
        # Run analysis
        if MCP_AVAILABLE:
            results = analyze_ioc_main(ioc)
        else:
            # Mock data for testing
            results = {
                "ioc": ioc,
                "ioc_type": "ip",
                "normalized_score": {
                    "final_score": 85,
                    "severity": "HIGH",
                    "priority": "P2"
                },
                "message": "Mock data - MCP server not available"
            }
        
        # Save to cache
        save_to_cache(ioc, results)
        
        # Rate limit info
        ip = request.remote_addr
        ip_count = get_ip_count_today(ip) + 1  # +1 for current query
        remaining = max(0, DAILY_LIMIT_PER_IP - ip_count)
        
        return jsonify({
            "cached": False,
            "ioc": ioc,
            "results": results,
            "rate_limit": {
                "remaining": remaining,
                "limit": DAILY_LIMIT_PER_IP
            }
        })
        
    except Exception as e:
        return jsonify({
            "error": "Analysis failed",
            "message": str(e)
        }), 500


@app.route('/api/stats', methods=['GET'])
def stats():
    """
    Public stats endpoint (no sensitive data)
    """
    from rate_limiter import get_global_count_today, get_monthly_count
    
    return jsonify({
        "platform_stats": {
            "queries_today": get_global_count_today(),
            "queries_this_month": get_monthly_count()
        },
        "your_stats": {
            "ip": request.remote_addr,
            "queries_today": get_ip_count_today(request.remote_addr),
            "remaining_today": max(0, DAILY_LIMIT_PER_IP - get_ip_count_today(request.remote_addr))
        }
    })


# Cleanup old data on startup
cleanup_old_data()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
