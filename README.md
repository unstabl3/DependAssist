# DependAssist

<p align="center">
  <img src="Images/logo.webp" alt="DependAssist Logo" width="200">
</p>

DependAssist is a powerful tool designed to streamline the process of managing Dependabot alerts and creating JIRA tickets. It automates the creation of JIRA issues for detected vulnerabilities, ensuring that your organization stays on top of security threats with minimal manual effort.

## Key Features

- **Automatic JIRA Ticket Creation**: Automatically creates JIRA tickets for Dependabot alerts.
- **Customizable Workflows**: Configure workflows and transitions to fit your organization's needs.
- **Team Mapping**: Automatically assigns issues to the correct teams based on repository mappings.
- **Custom Fields Support**: Easily include custom fields in JIRA tickets.
- **Severity Calculation**: Automatically calculate and assign issue severity based on various factors.

## Documentation

For detailed configuration and usage instructions, please visit our [documentation site](https://docs.shubhamchaskar.com).

## Quick Start

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables**:
   Create a `.env` file with your credentials:
   ```plaintext
   JIRA_APIKEY=your_jira_api_key_here
   JIRA_USERNAME=your_jira_username_here
   GITHUB_TOKEN=your_github_token_here
   ```

3. **Run the Script**:
   ```bash
   python main.py --config my.json
   ```


## License

DependAssist is released under the MIT License. See the [LICENSE](LICENSE) file for details.
