#!/usr/bin/env python3
"""
Script to fetch spreads automatically.
"""

import os
import requests
import sys
from datetime import datetime
import pytz
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def fetch_spreads():
    """Call the fetch_spreads API endpoint"""
    try:
        # Get the app URL and API key from environment variables
        app_url = os.environ.get('APP_URL', 'http://localhost:5000')
        api_key = os.environ.get('FETCH_SPREADS_API_KEY')
        
        if not api_key:
            print(f"[{datetime.now()}] Error: FETCH_SPREADS_API_KEY environment variable not set")
            return False
        
        headers = {'X-API-Key': api_key}
        response = requests.get(f"{app_url}/api/fetch_spreads", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            print(f"[{datetime.now()}] Successfully fetched spreads: {data.get('message', '')}")
            return True
        else:
            print(f"[{datetime.now()}] Failed to fetch spreads: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        print(f"[{datetime.now()}] Error fetching spreads: {str(e)}")
        return False

if __name__ == "__main__":
    success = fetch_spreads()
    sys.exit(0 if success else 1)
