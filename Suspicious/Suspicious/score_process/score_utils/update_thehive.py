import requests
from django.utils import timezone
from django.conf import settings
from datetime import datetime
from secrets import token_hex

def generate_ref():
    """
    Generate unique 'sourceRef' for an alert.
    """
    ref = datetime.now().strftime("%y%m%d") + "-" + str(token_hex(3))[:5]
    return ref

def create_new_alert(ticket_id, title, description, severity, thehive_url, api_key):
    if ticket_id is None:
        ticket_id = generate_ref()

    alert_data = {
        "title": title,
        "description": description,
        "severity": severity,
        "source": "suspicious",
        "sourceRef": ticket_id,
    }

    headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {api_key}'}

    url = f"{thehive_url}/api/v1/alert"
    try:
        response = requests.post(url, headers=headers, json=alert_data, verify=False)
        response.raise_for_status()
        alert=response.json()
        alert_id=alert["id"]

        return alert_id
    except Exception as e:
        print(f"Error creating alert: {e}")
        return f"Error creating alert: {e}"    
