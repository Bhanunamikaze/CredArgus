# CredArgus

_The all-seeing eye for your source code._

CredArgus is a powerful, multi-language credential scanner designed for penetration testers, Red Teamers, and developers. It recursively scans source code and configuration files to find hardcoded secrets, API keys, and other sensitive information, helping you secure your applications before they are deployed.

Based on the mythological giant Argus Panoptes, the hundred-eyed "all-seeing" watchman, this tool is built to be your vigilant guardian against credential exposure.

## Features

- **Polyglot Scanning:** Supports a wide range of programming and configuration languages.
    
- **Advanced Pattern Matching:** Utilizes a comprehensive list of regex patterns to detect everything from passwords and API keys to JWTs and private keys.
    
- **High-Entropy Analysis:** Identifies long, random-looking strings that are likely to be credentials, even without specific keywords.
    
- **Intelligent Filtering:**
    
    - **Allow List:** Use an `allow.txt` file to suppress false positives from known non-secret strings (e.g., API endpoints, UUIDs).
        
    - **Commit Hash Exclusion:** Automatically ignores Git commit hashes to reduce noise.
        
    - **Directory Exclusion:** Skips common directories like `.git`, `node_modules`, and `venv` by default, with options to add more.
        
- **Structured Reporting:** Outputs all findings to a clean, easy-to-parse `.csv` file for reporting and analysis.
    

## Supported Languages & Files

- **Programming Languages:** Python, Ruby, Perl, PHP, JavaScript (including JSX/TSX), Java, Go, C#, Shell Scripts.
    
- **Configuration Files:** `.env`, `.yml`, `.yaml`, `.json`, `.ini`, `.cfg`, `.conf`, `.xml`.
    

## Usage

CredArgus is a simple command-line tool. You only need Python 3 to run it.

1. **Clone the repository:**
    
    ```
    git clone [https://github.com/Bhanunamikaze/CredArgus.git](https://github.com/Bhanunamikaze/CredArgus.git)
    cd CredArgus
    ```
    
2. Run the scanner:
    
    Point it at the directory you want to scan.
    
    ```
    python CredArgus.py /path/to/your/project
    ```
    

### Command-Line Examples

Basic Scan:

Scans the specified directory and saves the results to credentials_report.csv.

```
python CredArgus.py /path/to/your/source/code
```

Specify Output File:

Use the -o or --output flag to name your report file.

```
python CredArgus.py /path/to/your/source/code -o my_project_findings.csv
```

Exclude Additional Directories:

Add more directories to the default exclusion list (.git, node_modules, venv).

```
python CredArgus.py /path/to/project --exclude-dir build dist assets
```

Using an Allow List to Reduce False Positives:

Create a file named allow.txt and use the --allow-file flag to ignore specific strings during "High Entropy" checks.

```
python CredArgus.py /path/to/project --allow-file allow.txt
```

Your `allow.txt` file should contain one string or substring per line that you want to ignore. For example:

```
# allow.txt
products/hosting/getAvailableDomainsForHostingPackage
a-known-uuid-or-identifier
another-safe-long-string
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.****
