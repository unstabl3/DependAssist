import requests
import time

def get_epss_score(cve_id):
    """Fetch the EPSS score for a given CVE ID."""
    time.sleep(1)
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(epss_url)
    if response.status_code == 200:
        data = response.json().get("data", [])
        if data:
            return data[0].get("epss"), epss_url
    return None, None


def check_kev_status(cve_id):
    """Check if the CVE ID exists in the KEV database using the JSON feed."""
    time.sleep(1)
    kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(kev_url)
    if response.status_code == 200:
        data = response.json().get("vulnerabilities", [])
        return any(vuln.get("cveID") == cve_id for vuln in data)
    return False
