import os
import re
import argparse
import csv
from typing import List, Tuple, Dict, Any

def get_all_patterns() -> Dict[str, List[Tuple[str, str]]]:
    """
    Returns a dictionary of regex patterns for each supported language and config file type.
    """
    # Base patterns for common secrets that can be reused across languages
    generic_secrets = [
        ("Generic API Key", r'["\']?api_key["\']?\s*[:=]\s*["\'][a-zA-Z0-9\-_]{16,}["\']'),
        ("Password Assignment", r'["\']?(password|passwd|pwd)["\']?\s*[:=]\s*["\'][^\s"\']{8,}["\']'),
        ("Secret Token", r'["\']?(secret|token)["\']?\s*[:=]\s*["\'][a-zA-Z0-9\-_.~+]{16,}["\']'),
        ("AWS Access Key ID", r'["\']?aws_access_key_id["\']?\s*[:=]\s*["\']AKIA[0-9A-Z]{16}["\']'),
        ("AWS Secret Access Key", r'["\']?aws_secret_access_key["\']?\s*[:=]\s*["\'][a-zA-Z0-9/+=]{40}["\']'),
        ("Google API Key", r'["\']?google_api_key["\']?\s*[:=]\s*["\']AIza[0-9A-Za-z\-_]{35}["\']'),
        ("Stripe API Key", r'["\']?stripe_key["\']?\s*[:=]\s*["\'](sk|pk)_(test|live)_[0-9a-zA-Z]{24}["\']'),
        ("GitHub Token", r'["\']?github_token["\']?\s*[:=]\s*["\']ghp_[a-zA-Z0-9]{36}["\']'),
        ("Slack Token", r'(xox[pboa]r?-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-f0-9]{32})'),
        ("JSON Web Token (JWT)", r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*'),
        ("Private Key", r'-----BEGIN (RSA|EC|PGP|OPENSSH) PRIVATE KEY-----'),
        ("High Entropy String", r'["\']([a-zA-Z0-9/+=]{40,})["\']'), # Catches long, random-looking strings
    ]

    patterns = {
        'python': generic_secrets + [
            ("Database Connection String", r'["\']?(db_url|database_url|connection_string)["\']?\s*[:=]\s*["\'][a-zA-Z0-9+://_.~%-]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+["\']'),
        ],
        'perl': [
            ("Generic API Key", r'\$(api_key|apikey)\s*=\s*["\'][a-zA-Z0-9\-_]{16,}["\'];'),
            ("Password Assignment", r'\$(password|passwd|pwd)\s*=\s*["\'][^\s"\']{8,}["\'];'),
            ("DBI Connection String", r'DBI->connect\(.*?,.*?,.*?["\'][^\s"\']{8,}["\']\)'),
        ] + generic_secrets,
        'ruby': [
            ("Generic API Key", r'api_key\s*(=>|=)\s*["\'][a-zA-Z0-9\-_]{16,}["\']'),
            ("Password Assignment", r'(password|passwd|pwd)\s*(=>|=)\s*["\'][^\s"\']{8,}["\']'),
            ("ENV Variable Assignment", r'ENV\[["\'](PASSWORD|SECRET_KEY|API_KEY)["\']\]\s*=\s*["\'].+["\']'),
        ] + generic_secrets,
        'php': [
            ("PHP MySQLi Connect", r'mysqli_connect\s*\(.*?,.*?,.*?,.*?\);'),
            ("PHP PDO Connection", r'new PDO\s*\([^)]+["\'][^"\']+["\']\s*\)'),
            ("PHP Password Variable", r'\$(password|passwd|pwd|pass|db_pass|user_pass|admin_pass)\s*=\s*["\'][^"\']+["\'];'),
            ("PHP Config Password", r'\$config\[["\']password["\']\]\s*=\s*["\'].+["\'];'),
            ("PHP Define Password", r'define\(\s*["\'](DB_PASSWORD|PASSWORD)["\']\s*,\s*["\'][^"\']+["\']\s*\)'),
            ("PHP Mailer Password", r'\$mail->Password\s*=\s*["\'][^"\']+["\'];'),
            ("Generic API Key", r'\$(api_key|apikey)\s*=\s*["\'][a-zA-Z0-9\-_]{16,}["\'];'),
        ] + generic_secrets,
        'javascript': generic_secrets,
        'java': [
            ("Password Assignment", r'String\s+(password|passwd|pwd)\s*=\s*"[^"]{8,}";'),
            ("JDBC Connection String", r'DriverManager\.getConnection\s*\(\s*"jdbc:.*?user=.*?password=.*?"\s*\)'),
            ("Generic API Key", r'String\s+(apiKey|api_key)\s*=\s*"[a-zA-Z0-9\-_]{16,}";'),
        ] + generic_secrets,
        'go': [
            ("Password Assignment", r'(password|passwd|pwd)\s*:=\s*"[^"]{8,}"'),
            ("SQL Connection String", r'sql\.Open\s*\(".*?"\s*,\s*".*?password=.*?"\)'),
        ] + generic_secrets,
        'csharp': [
             ("Connection String", r'connectionString\s*=\s*"[^"]*password=.*?"'),
             ("Password in AppSettings", r'<add\s+key="Password"\s+value=".*?"\s*/>'),
        ] + generic_secrets,
        'shell': [
            ("Exported Password", r'export\s+(password|passwd|pwd|secret|token|api_key)=["\']?[^"\']+["\']?'),
        ] + generic_secrets,
        'config': [ # For .env, .yaml, .json, .ini, .conf files
            ("Generic API Key", r'api_key\s*[:=]\s*[a-zA-Z0-9\-_]{16,}'),
            ("Password", r'password\s*[:=]\s*[^\s]{8,}'),
            ("Secret/Token", r'(secret|token)\s*[:=]\s*[a-zA-Z0-9\-_.~+]{16,}'),
        ] + generic_secrets
    }
    return patterns

def scan_file(file_path: str, lang: str, patterns: List[Tuple[str, str]], allow_list: List[str]) -> List[Dict[str, Any]]:
    """
    Scans a single file for credentials, ignoring lines with allowed substrings for high-entropy checks.
    """
    findings = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Skip commented out lines in most languages
                if line.strip().startswith(('#', '//', '/*', '*', '<!--')):
                    continue
                # Skip lines containing likely git commit hashes (40-char hex string) to reduce false positives
                if re.search(r'\b[a-f0-9]{40}\b', line, re.IGNORECASE):
                    continue
                for desc, pattern in patterns:
                    regex = re.compile(pattern, re.IGNORECASE)
                    if regex.search(line):
                        # If the finding is a "High Entropy String", check if it's on the allow list.
                        if desc == "High Entropy String" and allow_list:
                            is_allowed = False
                            for allowed_pattern in allow_list:
                                if allowed_pattern in line:
                                    is_allowed = True
                                    break
                            if is_allowed:
                                continue # Skip this specific finding as it's allowed.
                        
                        findings.append({
                            'file_path': file_path,
                            'line_number': line_num,
                            'language': lang,
                            'finding_type': desc,
                            'code_snippet': line.strip()
                        })
                        # Move to the next line after finding one match
                        break
    except Exception as e:
        print(f"[!] Error reading file {file_path}: {e}")
    return findings

def scan_directory(directory: str, excluded_dirs: List[str], allow_list: List[str]) -> List[Dict[str, Any]]:
    """
    Recursively scans a directory, determines file language, and aggregates findings.
    """
    all_findings = []
    all_patterns = get_all_patterns()
    lang_map = {
        '.py': ('python', all_patterns['python']),
        '.pl': ('perl', all_patterns['perl']), '.pm': ('perl', all_patterns['perl']),
        '.rb': ('ruby', all_patterns['ruby']),
        '.php': ('php', all_patterns['php']),
        '.js': ('javascript', all_patterns['javascript']), '.jsx': ('javascript', all_patterns['javascript']),
        '.ts': ('javascript', all_patterns['javascript']), '.tsx': ('javascript', all_patterns['javascript']),
        '.java': ('java', all_patterns['java']),
        '.go': ('go', all_patterns['go']),
        '.cs': ('csharp', all_patterns['csharp']),
        '.sh': ('shell', all_patterns['shell']), '.bash': ('shell', all_patterns['shell']),
        '.env': ('config', all_patterns['config']), '.yml': ('config', all_patterns['config']),
        '.yaml': ('config', all_patterns['config']), '.json': ('config', all_patterns['config']),
        '.conf': ('config', all_patterns['config']), '.ini': ('config', all_patterns['config']),
        '.cfg': ('config', all_patterns['config']), '.xml': ('config', all_patterns['config']),
    }

    print(f"\n[*] Starting CredArgus scan in directory: {directory}")
    for root, dirs, files in os.walk(directory):
        # Modify dirs in-place to prevent walking into excluded directories
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        
        for file in files:
            file_ext = os.path.splitext(file)[1]
            if file_ext in lang_map:
                lang, patterns = lang_map[file_ext]
                file_path = os.path.join(root, file)
                print(f"    -> Scanning {file_path} ({lang})")
                findings = scan_file(file_path, lang, patterns, allow_list)
                all_findings.extend(findings)
    
    return all_findings

def write_to_csv(findings: List[Dict[str, Any]], output_file: str):
    """
    Writes a list of findings to a CSV file.
    """
    if not findings:
        print("\n[+] No potential credentials found.")
        return

    print(f"\n[+] Found {len(findings)} potential credentials. Writing to {output_file}...")
    
    header = ['file_path', 'line_number', 'language', 'finding_type', 'code_snippet']
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            writer.writerows(findings)
        print(f"[+] Report successfully saved to {output_file}")
    except Exception as e:
        print(f"[!] Error writing to CSV file: {e}")

def main():
    """
    Main function to parse arguments and orchestrate the scan and report generation.
    """
    parser = argparse.ArgumentParser(
        prog="CredArgus",
        description="CredArgus: The all-seeing eye for your source code. A comprehensive credential scanner for various programming and configuration languages.",
        epilog="Example: python CredArgus.py /path/to/project -o report.csv --exclude-dir node_modules --allow-file allow.txt"
    )
    parser.add_argument("directory", help="The directory to scan recursively.")
    parser.add_argument("-o", "--output", default="credentials_report.csv", help="The name of the output CSV file (default: credentials_report.csv).")
    parser.add_argument("--exclude-dir", nargs='*', default=['node_modules', 'venv', '.git'], help="List of directory names to exclude from scanning.")
    parser.add_argument("--allow-file", help="Path to a file containing strings to exclude from 'High Entropy' checks, one per line.")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[-] Error: The specified path '{args.directory}' is not a valid directory.")
        return
        
    allow_list = []
    if args.allow_file:
        if os.path.exists(args.allow_file):
            print(f"[*] Loading allow list from {args.allow_file}")
            with open(args.allow_file, 'r', encoding='utf-8') as f:
                allow_list = [line.strip() for line in f if line.strip()]
        else:
            print(f"[-] Error: Allow list file '{args.allow_file}' not found.")
            return

    findings = scan_directory(args.directory, args.exclude_dir, allow_list)
    write_to_csv(findings, args.output)

if __name__ == "__main__":
    main()
