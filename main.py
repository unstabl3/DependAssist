import argparse
import os
from datetime import datetime, timedelta, timezone
from dependabot import fetch_dependabot_alerts, dismiss_dev_dependency_alert, dismiss_no_patch_alert
from jira_actions import initialize_jira, find_ticket_by_summary, is_advisory_url_in_issues, create_ticket, handle_development_dependency, move_ticket_to_next_state, handle_risk_accepted
from dotenv import load_dotenv
import json
from utils import load_configuration

def parse_args():
    parser = argparse.ArgumentParser(description="Fetch Dependabot alerts and create JIRA tickets.")
    parser.add_argument('--config', type=str, help='Path to the configuration file')
    return parser.parse_args()

def load_team_mappings(file_path):
    if not os.path.exists(file_path):
        print(f"Team mapping file not found at {file_path}.")
        return {}
    with open(file_path, 'r') as file:
        team_mappings = json.load(file)
    return team_mappings

def main():
    args = parse_args()
    load_dotenv()
    config = load_configuration(args.config)
    team_mapping_file = config['jira'].get('team_mapping_file')
    team_mappings = load_team_mappings(team_mapping_file) if config['jira'].get('process_jira_tickets', False) else {}
    jira = initialize_jira(config)

    org_name = config['github']['org_name']
    repo_file = config['settings']['repo_file']
    cutoff_days = config['settings']['cutoff_days']

    cutoff_date = datetime.now(timezone.utc) - timedelta(days=cutoff_days)
#    print(f"Organization Name: {org_name}")
#    print(f"Repository File: {repo_file}")
#    print(f"Cutoff Days: {cutoff_days}")

    try:
        with open(repo_file, 'r') as file:
            repo_names = [line.strip() for line in file]
            for repo_name in repo_names:
                print(f"Processing repository: {repo_name}")
                alerts = fetch_dependabot_alerts(org_name, repo_name, cutoff_date)
                for alert in alerts:
                    package_name = alert.get("dependency", {}).get("package", {}).get("name")
                    summary = f"Vulnerable Library - {repo_name} - {package_name}"
                    advisory_url = alert.get("html_url")
                    existing_tickets = find_ticket_by_summary(jira, config, summary)
                    vulnerabilities = alert.get("security_advisory", {}).get("vulnerabilities", [])
                    first_patched_version = next((vul.get("first_patched_version", {}).get("identifier") for vul in vulnerabilities if vul.get("first_patched_version")), None)

                    # Debug print statements
#                    print(f"Package Name: {package_name}")
#                    print(f"Summary: {summary}")
#                    print(f"Advisory URL: {advisory_url}")
#                    print(f"First Patched Version: {first_patched_version}")

                    if existing_tickets:
                        if is_advisory_url_in_issues(existing_tickets, advisory_url):
                            print(f"Ticket already exists with advisory URL: {advisory_url}")
                        else:
                            print(f"No existing ticket found with advisory URL for alert: {summary}. Creating new ticket...")
                            if alert.get("dependency", {}).get("scope") == "development":
                                handle_development_dependency(jira, config, repo_name, alert)
                                if config['jira'].get('process_jira_tickets', False):
                                    dismiss_dev_dependency_alert(org_name, repo_name, alert)
                            else:
                                if not first_patched_version:
                                    handle_risk_accepted(jira, config, repo_name, alert)
                                    if config['jira'].get('dismiss_no_patch', False):
                                        dismiss_no_patch_alert(org_name, repo_name, alert)
                                else:
                                    new_issue = create_ticket(jira, config, repo_name, alert, team_mappings)
                                    if new_issue and config['jira'].get('process_jira_tickets', False):
                                        normal_workflow_states = config['jira']['workflow_states']['normal']
                                        for state in normal_workflow_states[1:]:  # Skip the initial state as it's the default on creation
                                            move_ticket_to_next_state(jira, new_issue, state)
                    else:
                        print(f"No existing ticket found for alert: {summary}. Creating new ticket...")
                        if alert.get("dependency", {}).get("scope") == "development":
                            handle_development_dependency(jira, config, repo_name, alert)
                            if config['jira'].get('process_jira_tickets', False):
                                dismiss_dev_dependency_alert(org_name, repo_name, alert)
                        else:
                            if not first_patched_version:
                                handle_risk_accepted(jira, config, repo_name, alert)
                                if config['jira'].get('dismiss_no_patch', False):
                                    dismiss_no_patch_alert(org_name, repo_name, alert)
                            else:
                                new_issue = create_ticket(jira, config, repo_name, alert, team_mappings)
                                if new_issue and config['jira'].get('process_jira_tickets', False):
                                    normal_workflow_states = config['jira']['workflow_states']['normal']
                                    for state in normal_workflow_states[1:]:  # Skip the initial state as it's the default on creation
                                        move_ticket_to_next_state(jira, new_issue, state)
    except FileNotFoundError:
        print(f"Error: The repository file '{repo_file}' does not exist.")
        exit(1)

if __name__ == '__main__':
    main()
