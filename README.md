# A1OSINT - The Ultimate OSINT Intelligence Entity

A professional-grade autonomous intelligence gathering platform with built-in data libraries and deep analysis capabilities.

## Features

*   **Autonomous Intelligence Gathering:** A1OSINT can autonomously investigate targets, pivoting between different data points to uncover new information.
*   **Multiple Target Types:** Supports various target types, including usernames, emails, domains, IP addresses, and more.
*   **Deep Profile Analysis:** Utilizes Selenium to perform in-depth analysis of social media profiles on platforms like GitHub and Reddit.
*   **Relevance Filtering:** Intelligently filters out noise and low-confidence findings to present only the most relevant intelligence.
*   **Built-in Data Libraries:** Includes libraries for known data breaches and malicious IP addresses (can be populated by the user).
*   **Professional Reporting:** Generates a clean, professional intelligence report in the terminal.
*   **Extensible:** The platform can be easily extended with new sites and data sources by modifying the `sites.json` file.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/DCXII/A1O.git
    cd A1O
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run A1OSINT, you need to provide a target type and a value.

```bash
python osint.py <type> <value> [options]
```

**Available Types:**
*   `username`
*   `email`
*   `domain`
*   `ip`
*   `person`
*   `phone`
*   `url`

**Options:**
*   `-D, --depth`: Investigation depth (default: 2).
*   `-v, --verbose`: Verbose output.
*   `-o, --output`: Save the report to a JSON file.
*   `--proxy`: Use a proxy (e.g., `http://host:port`).
*   `--browser`: Browser to use for deep analysis (`chrome` or `firefox`, default: `chrome`).
*   `--no-banner`: Hide the banner.
*   `--no-consent`: Skip the consent prompt.

**Examples:**

*   **Investigate a username:**
    ```bash
    python osint.py username DCXII -v
    ```

*   **Investigate an email with a specific depth:**
    ```bash
    python osint.py email example@example.com -D 3
    ```

*   **Investigate a domain and save the report:**
    ```bash
    python osint.py domain example.com -o report.json
    ```

## Configuration

*   **`config.ini`:** (Not yet implemented, but planned for future use to configure API keys and other settings).
*   **`sites.json`:** This file contains the list of websites to check for usernames. You can add more sites by following the existing format. The `errorType` can be `status_code` (expects a 200 OK) or `message` (expects the `errorMsg` not to be in the page content).
*   **`breach_library.json`:** A user-populated database of known data breaches. The key is the email address, and the value is an array of breach names.
*   **`ip_library.json`:** A user-populated database of known malicious IP addresses. The key is the IP address, and the value is a description of the threat.

## Dependencies

The following Python libraries are required:

*   requests
*   dnspython
*   python-whois
*   beautifulsoup4
*   Pillow
*   robotexclusionrulesparser
*   selenium
*   webdriver-manager

All dependencies are listed in the `requirements.txt` file.

## Disclaimer

This tool is intended for legal and ethical purposes only. Before running a search, you will be prompted to agree to a legal disclaimer. The developer is not responsible for any illegal usage of this tool.

## License

This project is currently unlicensed. You are free to use, modify, and distribute it as you see fit. However, a formal license may be added in the future.
