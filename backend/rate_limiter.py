"""
Rate Limiting & Cost Protection
Prevents API abuse and cost overruns
"""

import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
import hashlib

# Configuration
DAILY_LIMIT_PER_IP = 5
GLOBAL_DAILY_LIMIT = 100
GLOBAL_MONTHLY_LIMIT = 500
CACHE_TTL_HOURS = 24
SHODAN_CACHE_DAYS = 7

DB_PATH = 'rate_limits.db'


def init_db():
    """Initialize SQLite database for rate limiting and caching"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Rate limits table
    c.execute('''CREATE TABLE IF NOT EXISTS rate_limits
                 (ip TEXT, date TEXT, count INTEGER, 
                  PRIMARY KEY (ip, date))''')
    
    # Global limits table
    c.execute('''CREATE TABLE IF NOT EXISTS global_limits
                 (date TEXT PRIMARY KEY, count INTEGER)''')
    
    # Monthly limits table
    c.execute('''CREATE TABLE IF NOT EXISTS monthly_limits
                 (month TEXT PRIMARY KEY, count INTEGER)''')
    
    # Cache table
    c.execute('''CREATE TABLE IF NOT EXISTS cache
                 (ioc_hash TEXT PRIMARY KEY, 
                  ioc TEXT,
                  results TEXT,
                  cached_at TEXT,
                  expires_at TEXT)''')
    
    # Shodan cache (longer TTL)
    c.execute('''CREATE TABLE IF NOT EXISTS shodan_cache
                 (ip TEXT PRIMARY KEY,
                  results TEXT,
                  cached_at TEXT,
                  expires_at TEXT)''')
    
    conn.commit()
    conn.close()


def get_ip_count_today(ip):
    """Get query count for IP today"""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT count FROM rate_limits WHERE ip=? AND date=?', (ip, today))
    result = c.fetchone()
    conn.close()
    return result[0] if result else 0


def increment_ip_count(ip):
    """Increment query count for IP"""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO rate_limits (ip, date, count) VALUES (?, ?, 1)
                 ON CONFLICT(ip, date) DO UPDATE SET count = count + 1''', 
              (ip, today))
    conn.commit()
    conn.close()


def get_global_count_today():
    """Get global query count today"""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT count FROM global_limits WHERE date=?', (today,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else 0


def increment_global_count():
    """Increment global query count"""
    today = datetime.now().strftime('%Y-%m-%d')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO global_limits (date, count) VALUES (?, 1)
                 ON CONFLICT(date) DO UPDATE SET count = count + 1''', 
              (today,))
    conn.commit()
    conn.close()


def get_monthly_count():
    """Get global query count this month"""
    month = datetime.now().strftime('%Y-%m')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT count FROM monthly_limits WHERE month=?', (month,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else 0


def increment_monthly_count():
    """Increment monthly query count"""
    month = datetime.now().strftime('%Y-%m')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO monthly_limits (month, count) VALUES (?, 1)
                 ON CONFLICT(month) DO UPDATE SET count = count + 1''', 
              (month,))
    conn.commit()
    conn.close()


def hours_until_reset():
    """Calculate hours until daily reset"""
    now = datetime.now()
    tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return round((tomorrow - now).total_seconds() / 3600, 1)


def get_reset_timestamp():
    """Get Unix timestamp of next reset"""
    tomorrow = (datetime.now() + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(tomorrow.timestamp())


def get_from_cache(ioc):
    """Get cached results for IOC"""
    ioc_hash = hashlib.sha256(ioc.lower().encode()).hexdigest()
    now = datetime.now().isoformat()
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''SELECT results FROM cache 
                 WHERE ioc_hash=? AND expires_at > ?''', 
              (ioc_hash, now))
    result = c.fetchone()
    conn.close()
    
    return result[0] if result else None


def save_to_cache(ioc, results):
    """Save analysis results to cache"""
    import json
    
    ioc_hash = hashlib.sha256(ioc.lower().encode()).hexdigest()
    now = datetime.now()
    expires = now + timedelta(hours=CACHE_TTL_HOURS)
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR REPLACE INTO cache 
                 (ioc_hash, ioc, results, cached_at, expires_at)
                 VALUES (?, ?, ?, ?, ?)''',
              (ioc_hash, ioc, json.dumps(results), 
               now.isoformat(), expires.isoformat()))
    conn.commit()
    conn.close()


def rate_limit(f):
    """Rate limiting decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        
        # Check IP limit
        ip_count = get_ip_count_today(ip)
        if ip_count >= DAILY_LIMIT_PER_IP:
            return jsonify({
                "error": "Rate limit exceeded",
                "message": f"Daily limit of {DAILY_LIMIT_PER_IP} queries reached. Reset in {hours_until_reset()} hours.",
                "limit": DAILY_LIMIT_PER_IP,
                "remaining": 0,
                "reset_hours": hours_until_reset()
            }), 429
        
        # Check global daily limit
        global_count = get_global_count_today()
        if global_count >= GLOBAL_DAILY_LIMIT:
            return jsonify({
                "error": "Global daily limit exceeded",
                "message": "Platform daily quota reached. Try again tomorrow.",
                "retry_after_hours": hours_until_reset()
            }), 429
        
        # Check monthly limit
        monthly_count = get_monthly_count()
        if monthly_count >= GLOBAL_MONTHLY_LIMIT:
            return jsonify({
                "error": "Monthly limit exceeded",
                "message": "Platform monthly quota reached. Service temporarily unavailable."
            }), 429
        
        # Execute function
        response = f(*args, **kwargs)
        
        # Only increment if not from cache
        if not (isinstance(response, tuple) and len(response) > 0 and 
                isinstance(response[0].json, dict) and 
                response[0].json.get('cached')):
            increment_ip_count(ip)
            increment_global_count()
            increment_monthly_count()
        
        # Add rate limit headers
        if isinstance(response, tuple):
            resp_obj, status_code = response
        else:
            resp_obj = response
            status_code = 200
        
        remaining = max(0, DAILY_LIMIT_PER_IP - ip_count - 1)
        resp_obj.headers['X-RateLimit-Limit'] = str(DAILY_LIMIT_PER_IP)
        resp_obj.headers['X-RateLimit-Remaining'] = str(remaining)
        resp_obj.headers['X-RateLimit-Reset'] = str(get_reset_timestamp())
        
        return resp_obj, status_code
    
    return decorated_function


def cleanup_old_data():
    """Cleanup expired cache and old rate limit data"""
    now = datetime.now().isoformat()
    old_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Delete expired cache
    c.execute('DELETE FROM cache WHERE expires_at < ?', (now,))
    c.execute('DELETE FROM shodan_cache WHERE expires_at < ?', (now,))
    
    # Delete old rate limits
    c.execute('DELETE FROM rate_limits WHERE date < ?', (old_date,))
    
    conn.commit()
    conn.close()
