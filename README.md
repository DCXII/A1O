# A1OSINT - The Ultimate OSINT Intelligence Entity

A professional-grade autonomous intelligence gathering platform with **AI-powered analysis**, built-in data libraries, and deep investigation capabilities.

## Features

*   **[AI] AI-Powered Analysis (NEW):** Integrates Google Gemini AI for intelligent profile analysis, cross-platform correlation, entity extraction, and AI-written intelligence reports.
*   **Autonomous Intelligence Gathering:** A1OSINT can autonomously investigate targets, pivoting between different data points to uncover new information.
*   **Multiple Target Types:** Supports various target types, including usernames, emails, domains, IP addresses, and more.
*   **Deep Profile Analysis:** Utilizes Selenium to perform in-depth analysis of social media profiles on platforms like GitHub and Reddit.
*   **Relevance Filtering:** Intelligently filters out noise and low-confidence findings to present only the most relevant intelligence.
*   **Built-in Data Libraries:** Includes libraries for known data breaches and malicious IP addresses (can be populated by the user).
*   **Professional Reporting:** Generates a clean, professional intelligence report - or an AI-written executive brief with the `--ai` flag.
*   **Extensible:** The platform can be easily extended with new sites and data sources by modifying the `sites.json` file.

## AI Brain Features

When `--ai` is enabled:

*   **Dual-Backend Support:** 
    *   **Gemini (Cloud):** High-performance, requires API key in `config.ini`.
    *   **Ollama (Local):** Private, runs locally, **no API key needed**. Supports models like `qwen2:1.5b`, `llama3.2:3b`, etc.
*   **Profile Intelligence:** AI analyzes scraped profile data to extract personality insights, behavioral patterns, and interests.
*   **Cross-Platform Correlation:** Automatically correlates findings across all platforms to identify identity connections and patterns.
*   **Smart Entity Extraction:** AI discovers entities that regex-based extraction would miss - organizations, technologies, locations, etc.
*   **Risk Assessment:** Flags privacy risks, exposed credentials, and potential security concerns.
*   **Investigation Leads:** Suggests what to investigate next, ranked by potential intelligence value.
*   **AI Reports:** Generates comprehensive, AI-written intelligence briefs instead of template-based output.

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

3.  **Run the installation script:**
    ```bash
    chmod +x install.sh
    ./install.sh
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
*   `--ai`: Enable AI-powered analysis (requires Gemini API key in `config.ini`).
*   `--no-banner`: Hide the banner.

**Examples:**

*   **Investigate a username:**
    ```bash
    python osint.py username DCXII -v
    ```

*   **Investigate an email with a specific depth:**
    ```bash
    python osint.py email example@example.com -D 3
    ```

*   **Investigate a domain with local AI (no API key):**
    ```bash
    python osint.py domain example.com --ai ollama
    ```

*   **`config.ini`:** Configure your Gemini API key here for cloud AI analysis.
*   **`sites.json`:** This file contains the list of websites to check for usernames. You can add more sites by following the existing format.

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
