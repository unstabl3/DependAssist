import os
from jira import JIRA
from dotenv import load_dotenv
from utils import load_configuration
from epss_kev import get_epss_score, check_kev_status
from vuln_rating import calculate_severity
import re	
load_dotenv()

def initialize_jira(config):
    """Initialize the JIRA client."""
    jira_options = {
        'server': config['jira']['server']
    }
    jira = JIRA(options=jira_options, basic_auth=(os.getenv('JIRA_USERNAME'), os.getenv('JIRA_APIKEY')))

    field_metadata = jira.fields()
    team_field_id = config['jira'].get('team_field_id')
    team_field_allows_multiple = False
    custom_fields_metadata = {}

    for field in field_metadata:
        if field['id'] == team_field_id:
            team_field_allows_multiple = field['schema'].get('type') == 'array'
            break
    
    config['jira']['team_field_allows_multiple'] = team_field_allows_multiple
    for field in field_metadata:
        field_id = field['id']
        if field_id in config['jira']['custom_fields']:
            allows_multiple = field.get('type') == 'array'
            custom_fields_metadata[field_id] = {'allows_multiple': allows_multiple}
    
    config['jira']['custom_fields_metadata'] = custom_fields_metadata
    return jira

def find_ticket_by_summary(jira, config, summary):
    """Search for a Jira ticket by its exact summary."""
    project_key = config['jira']['project_key']
    status_values = config['jira']['status_values']
    
    status_list = ', '.join([f'"{status}"' for status in status_values])
    print(f"[DEBUG] Searching for ticket with summary: {summary}")
    jql_query = (f'project = {project_key} AND '
                 f'status IN ({status_list}) AND summary ~ "\\"{summary}\\""')

    issues = jira.search_issues(jql_query)
    return issues

def is_advisory_url_in_issues(issues, advisory_url):
    """Check if the advisory URL is present in the description of the issues."""
    for issue in issues:
        if advisory_url in issue.fields.description:
            return True
    return False

def convert_markdown_to_jira(markdown_text):
    # Convert headers
    markdown_text = re.sub(r'^### (.*)', r'h3. \1', markdown_text, flags=re.MULTILINE)
    markdown_text = re.sub(r'^## (.*)', r'h2. \1', markdown_text, flags=re.MULTILINE)
    markdown_text = re.sub(r'^# (.*)', r'h1. \1', markdown_text, flags=re.MULTILINE)
    
    # Convert bold and italics
    markdown_text = re.sub(r'\*\*(.*?)\*\*', r'*\1*', markdown_text)  # bold
    markdown_text = re.sub(r'\*(.*?)\*', r'_\1_', markdown_text)  # italics
    
    # Convert inline code
    markdown_text = re.sub(r'`([^`]+)`', r'{{\1}}', markdown_text)
    
    # Convert links
    markdown_text = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', r'[\1|\2]', markdown_text)
    
    # Convert lists
    markdown_text = re.sub(r'^\* ', r'* ', markdown_text, flags=re.MULTILINE)
    markdown_text = re.sub(r'^\- ', r'* ', markdown_text, flags=re.MULTILINE)
    markdown_text = re.sub(r'^\d+\. ', r'# ', markdown_text, flags=re.MULTILINE)

    return markdown_text

def create_ticket(jira, config, repo_name, alert, team_mappings):
    """Create a Jira ticket for a given alert."""
    advisory_url = alert.get("html_url")
    repo_url = f"https://github.com/{config['github']['org_name']}/{repo_name}"
    dependency_name = alert.get("dependency", {}).get("package", {}).get("name")
    description_text = alert.get("security_advisory", {}).get("description")
    description_text = convert_markdown_to_jira(description_text)
#    print(description_text)
    cve_id = alert.get("security_advisory", {}).get("cve_id")
    severity = alert.get("security_advisory", {}).get("severity").lower()
    summary = f"Vulnerable Library - {repo_name} - {dependency_name}"
    issuetype = config['jira']['issuetype']
    project_key = config['jira']['project_key']

    # Get EPSS score and KEV status
    epss_score, epss_link = get_epss_score(cve_id) if cve_id else (None, None)
    kev_status = check_kev_status(cve_id) if cve_id else False
    cvss_score = alert.get("security_advisory", {}).get("cvss", {}).get("score")
    cvss_vector = alert.get("security_advisory", {}).get("cvss", {}).get("vector_string")
    epss_score = float(epss_score) if epss_score is not None else 0.0

    solution_info = "No patch available"
    vulnerabilities = alert.get("security_advisory", {}).get("vulnerabilities", [])
    first_patched_version = next((vul.get("first_patched_version", {}).get("identifier") for vul in vulnerabilities if vul.get("first_patched_version")), None)
    if first_patched_version:
        solution_info = f"Upgrade to {first_patched_version} or later."

    description = f"""
h2. Vulnerability Details

*Advisory Link*:

- {advisory_url}

*Repository*: {repo_url}

*Dependency*: {dependency_name}

*Solution*: {solution_info}

*Description*: 
{description_text}

*EPSS Score*: {epss_score or 'Not Available'}
*EPSS Link*: {epss_link or 'Not Available'}

*KEV Status*: {"Found" if kev_status else "Not Found"}
*CVSS Score*: {cvss_score if cvss_score is not None else 'Not Available'}
*CVSS Vector*: {cvss_vector if cvss_vector is not None else 'Not Available'}
"""
#    print(project_key)
#    print(issuetype)
    fields = {
        'project': {'key': project_key},
        'summary': summary,
        'description': description,
        'issuetype': {'name': issuetype}
    }

    # Add custom fields
    custom_fields_metadata = config['jira'].get('custom_fields_metadata', {})
    if 'custom_fields' in config['jira']:
        for field_id, field_value in config['jira']['custom_fields'].items():
            allows_multiple = custom_fields_metadata.get(field_id, {}).get('allows_multiple', False)
            if allows_multiple:
                if not isinstance(field_value, list):
                    field_value = [field_value]
                fields[field_id] = [{'id': val} for val in field_value]
            else:
                if isinstance(field_value, list):
                    field_value = field_value[0]  # Use the first value if multiple are provided
                fields[field_id] = {'id': field_value}

    if config['jira'].get('auto_severity', False):
        severity = calculate_severity(cvss_score, epss_score, kev_status)
        severity_fields = config['jira'].get('severity_fields', {})
        for severity_field, severity_values in severity_fields.items():
            if severity in severity_values['values']:
                fields[severity_field] = {'id': severity_values['values'][severity]}

    if config['jira'].get('process_jira_tickets', False):
        # Assign team based on repo_name
        team_field_id = config['jira'].get('team_field_id')
        team_id = team_mappings.get(repo_name)
        team_field_allows_multiple = config['jira'].get('team_field_allows_multiple', False)
        if team_field_id and team_id:
            if team_field_allows_multiple:
                if not isinstance(team_id, list):
                    team_id = [team_id]
                fields[team_field_id] = [{'id': t_id} for t_id in team_id]
            else:
                if isinstance(team_id, list):
                    team_id = team_id[0]  # Use the first team ID
                fields[team_field_id] = {'id': team_id}

    new_issue = jira.create_issue(fields=fields)

    print(f"Created ticket: {new_issue.key}")
    return new_issue

def handle_development_dependency(jira, config, repo_name, alert):
    """Handle the creation of a Jira ticket for development dependencies."""
    new_issue = create_ticket(jira, config, repo_name, alert)

    if new_issue:
        comment = "This is the development dependency and vulnerable code is not used in production"
        jira.add_comment(new_issue.key, comment)
        if config['jira'].get('process_jira_tickets', False):
            dev_workflow_states = config['jira']['workflow_states']['dev_dependency']
            for state in dev_workflow_states[1:]:  # Skip the initial state as it's the default on creation
                move_ticket_to_next_state(jira, new_issue, state)

def handle_risk_accepted(jira, config, repo_name, alert):
    """Handle the transition for risk accepted tickets."""
    new_issue = create_ticket(jira, config, repo_name, alert)

    if new_issue:
        comment = "There is no patch available for this alert."
        jira.add_comment(new_issue.key, comment)
        
        if config['jira'].get('process_jira_tickets', False):
            risk_workflow_states = config['jira']['workflow_states']['risk_accepted']
            for state in risk_workflow_states[1:]:  # Skip the initial state as it's the default on creation
                move_ticket_to_next_state(jira, new_issue, state)
        
        if config['jira'].get('link_issue', False):
            outward_issue_key = config['jira']['outward_issue_key']
            link_type = config['jira']['link_type']
            jira.create_issue_link(type=link_type, inwardIssue=new_issue.key, outwardIssue=outward_issue_key)

def move_ticket_to_next_state(jira, issue, next_state):
    """Move a Jira ticket to the next state."""
    transitions = jira.transitions(issue)
    transition_id = None
    for transition in transitions:
        if transition['name'].lower() == next_state.lower():
            transition_id = transition['id']
            break
    if transition_id:
        jira.transition_issue(issue, transition_id)
        print(f"Moved ticket {issue.key} to {next_state} state.")
    else:
        print(f"No transition found for next state: {next_state}")
