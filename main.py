import argparse
import re
import os
import logging
import sys
import hashlib
import json  # For handling JSON data if needed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def _mask_value(value):
    """Masked preview only: first 4 characters plus a short hash."""
    digest = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:8]
    return f"{value[:4]}...[REDACTED sha256:{digest}]"


class APIKeyScanner:
    """
    A class to scan local files and directories for exposed API keys and secrets.
    It does not scan network traffic.
    """

    def __init__(self, target, file_types=None, regex_patterns=None, exclude_paths=None):
        """
        Initializes the APIKeyScanner.

        Args:
            target (str): The target path (a local file or directory).
            file_types (list, optional): List of file extensions to scan. Defaults to None (all files).
            regex_patterns (list, optional): List of regex patterns to use for key detection. Defaults to common patterns.
            exclude_paths (list, optional): List of paths to exclude from the scan. Defaults to None.
        """

        self.target = target
        self.file_types = file_types
        if regex_patterns:
            self.regex_patterns = list(regex_patterns)
            self.pattern_names = [f"custom_pattern_{i + 1}" for i in range(len(self.regex_patterns))]
        else:
            named = self._default_regex_patterns()
            self.pattern_names = [name for name, _ in named]
            self.regex_patterns = [pat for _, pat in named]
        for pat in self.regex_patterns:
            try:
                re.compile(pat)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern {pat!r}: {e}")
        self.exclude_paths = exclude_paths or []
        self.files_scanned = 0

        # Input validation
        if not isinstance(self.target, str):
            raise TypeError("Target must be a string.")
        if self.file_types and not isinstance(self.file_types, list):
            raise TypeError("File types must be a list.")
        if not isinstance(self.regex_patterns, list):
            raise TypeError("Regex patterns must be a list.")
        if not isinstance(self.exclude_paths, list):
            raise TypeError("Exclude paths must be a list.")

    def _default_regex_patterns(self):
        """
        Returns a list of default regex patterns for common API keys and secrets.
        """
        return [
            ("aws_access_key", r"(?i)AKIA[0-9A-Z]{16}"),
            ("secret_key", r"(?i)secret_key=[\"']?[0-9a-zA-Z+/=]{40}[\"']?"),
            ("generic_api_key_32", r"(?i)api_key=[\"']?[0-9a-zA-Z]{32}[\"']?"),
            ("generic_api_key_40", r"(?i)api_key=[\"']?[0-9a-zA-Z]{40}[\"']?"),
            ("rsa_private_key", r"(?i)-----BEGIN RSA PRIVATE KEY-----"),
            ("pgp_private_key", r"(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----"),
            ("openssh_private_key", r"(?i)-----BEGIN OPENSSH PRIVATE KEY-----"),
            ("openai_api_key", r"sk-[a-zA-Z0-9]{32,}"),
            ("google_cloud_api_key", r"AIzaSy[a-zA-Z0-9_-]{35}"),
            ("firebase_key", r"\b[a-zA-Z0-9_-]{32}\.[a-zA-Z0-9_-]{59}\b"),
            ("slack_bot_token", r"xoxb-[0-9]{11}-[0-9]{12}"),
            ("github_personal_access_token", r"ghp_[a-zA-Z0-9]{36}"),
        ]

    def scan_file(self, file_path):
        """
        Scans a single file for API keys and secrets.

        Args:
            file_path (str): The path to the file.

        Returns:
            list: A list of tuples, where each tuple contains the line number and the matched string.
        """

        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        self.files_scanned += 1

        matches = []
        for i, line in enumerate(lines):
            for name, pattern in zip(self.pattern_names, self.regex_patterns):
                match = re.search(pattern, line)
                if match:
                    raw = match.group(0).strip()
                    matches.append({"line": i + 1, "pattern": name, "match_masked": _mask_value(raw)})
        return matches

    def scan_directory(self, directory_path):
        """
        Scans all files in a directory (recursively) for API keys and secrets.

        Args:
            directory_path (str): The path to the directory.

        Returns:
            dict: A dictionary where keys are file paths and values are lists of matches (line number, matched string).
        """
        results = {}
        exclude_abs = [os.path.abspath(p) for p in self.exclude_paths]
        # Also resolve exclude entries given relative to the scanned tree.
        for p in self.exclude_paths:
            candidate = os.path.abspath(os.path.join(directory_path, p))
            if candidate not in exclude_abs:
                exclude_abs.append(candidate)

        def _excluded(path):
            ap = os.path.abspath(path)
            return any(ap == ex or ap.startswith(ex + os.sep) for ex in exclude_abs)

        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if not _excluded(os.path.join(root, d))]
            if _excluded(root):
                continue

            for file in files:
                file_path = os.path.join(root, file)

                # Check file type if specified
                if self.file_types and not any(file.endswith(ext) for ext in self.file_types):
                    continue

                matches = self.scan_file(file_path)
                if matches:
                    results[file_path] = matches
        return results

    def scan_network_traffic(self, traffic_file_path):
        """
        Network traffic scanning is not implemented. This tool scans
        local files and directories only.
        """
        raise NotImplementedError("Network traffic scanning is not implemented; this tool scans local files and directories only.")

    def scan(self):
        """
        Scans the target (a local file or directory) for API keys and secrets.

        Returns:
            dict: Results of the scan.

        Raises:
            FileNotFoundError: when the target does not exist.
            Exception: any scan failure propagates instead of being
            folded into an empty, clean-looking result.
        """
        if os.path.isfile(self.target):
            logging.info(f"Scanning file: {self.target}")
            results = {self.target: self.scan_file(self.target)}
        elif os.path.isdir(self.target):
            logging.info(f"Scanning directory: {self.target}")
            results = self.scan_directory(self.target)
        else:
            raise FileNotFoundError(f"Target is not a valid file or directory: {self.target}")
        return results

def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans local files and directories for exposed API keys and secrets. It does not scan network traffic.")
    parser.add_argument("target", help="The target local file or directory to scan.")
    parser.add_argument("-f", "--file-types", nargs="+", help="List of file extensions to scan (e.g., .txt .py .js). If not specified, all files are scanned in a directory.")
    parser.add_argument("-e", "--exclude", nargs="+", help="List of paths to exclude from the scan (directories).")
    parser.add_argument("-o", "--output", help="Output file to write results to (JSON format).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (debug level).")
    parser.add_argument("-p", "--patterns", nargs="+", help="List of custom regex patterns to use for key detection.  Use with caution!")
    return parser


def main():
    """
    Main function to parse arguments, run the scanner, and print the results.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        scanner = APIKeyScanner(args.target, file_types=args.file_types, exclude_paths=args.exclude, regex_patterns=args.patterns)
        results = scanner.scan()
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        print("Scan not performed or failed. No clean verdict issued.")
        sys.exit(1)

    if scanner.files_scanned == 0:
        print("Scan not performed: no files were read. No clean verdict issued.")
        sys.exit(2)

    total = sum(len(m) for m in results.values())
    if total:
        print("Scan results:")
        for file_path, matches in results.items():
            if matches:
                print(f"  File: {file_path}")
                for entry in matches:
                    print(f"    Line {entry['line']}: pattern={entry['pattern']} match={entry['match_masked']}")
    else:
        print("No API keys or secrets found.")

    if args.output:
        try:
            with open(args.output, 'w') as outfile:
                json.dump(results, outfile, indent=4)
            print(f"Results written to {args.output}")
        except Exception as e:
            logging.error(f"Error writing results to file: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()

# Example Usage:
# 1. Scan a single file: python vuln_API_Key_Exposure_Scanner.py my_config.txt
# 2. Scan a directory: python vuln_API_Key_Exposure_Scanner.py /path/to/codebase
# 3. Scan a directory, excluding a subdirectory: python vuln_API_Key_Exposure_Scanner.py /path/to/codebase -e /path/to/codebase/venv
# 4. Scan a directory, only looking for .py and .js files: python vuln_API_Key_Exposure_Scanner.py /path/to/codebase -f .py .js
# 5. Scan a file and write the results to a JSON file: python vuln_API_Key_Exposure_Scanner.py my_config.txt -o results.json
# 6. Enable verbose logging: python vuln_API_Key_Exposure_Scanner.py my_config.txt -v
# 7. Provide a custom regex pattern: python vuln_API_Key_Exposure_Scanner.py my_config.txt -p "YOUR_CUSTOM_REGEX"