import requests
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
load_dotenv()

HEADERS = {
    "Authorization": f"token {os.getenv('GITHUB_TOKEN')}",
    "Accept": "application/vnd.github.dorian-preview+json"
}

DISMISS_ALERT_URL = "https://api.github.com/repos/{org_name}/{repo}/dependabot/alerts/{alert}"
GITHUB_API_URL_TEMPLATE = "https://api.github.com/repos/{org_name}/{repo_name}/dependabot/alerts?state=open"

def fetch_dependabot_alerts(org_name, repo_name, cutoff_date):
    GITHUB_API_URL = GITHUB_API_URL_TEMPLATE.format(org_name=org_name, repo_name=repo_name)
    print(GITHUB_API_URL)
    response = requests.get(GITHUB_API_URL, headers=HEADERS)
    if response.status_code != 200:
        print(f"Failed to fetch alerts for {repo_name}. Status: {response.status_code}, Message: {response.text}")
        return []

    all_alerts = response.json()
    recent_alerts = [
        alert for alert in all_alerts
        if datetime.strptime(alert.get("created_at", ""), '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) > cutoff_date
    ]
    return recent_alerts

def dismiss_dev_dependency_alert(org_name, repo_name, alert):
    dismiss_alert(org_name, repo_name, alert, "not_used", "This is a development dependency and vulnerable code is not used in production")

def dismiss_no_patch_alert(org_name, repo_name, alert):
    dismiss_alert(org_name, repo_name, alert, "no_bandwidth", "No patch available")

def dismiss_alert(org_name, repo_name, alert, dismissed_reason, comment):
    url = DISMISS_ALERT_URL.format(org_name=org_name, repo=repo_name, alert=alert["number"])
    data = {
        "state": "dismissed",
        "dismissed_reason": dismissed_reason,
        "dismissed_comment": comment
    }
    response = requests.patch(url, headers=HEADERS, json=data)
    if response.status_code in [200, 204]:
        print(f"Dismissed alert: https://github.com/org_name/{repo_name}/security/dependabot/{alert['number']}")
    else:
        print(f"Failed to dismiss alert {alert} for {repo_name}. Status code: {response.status_code}. Message: {response.text}")
