import argparse
import re
import os
import logging
import sys
import requests
import json  # For handling JSON data if needed

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class APIKeyScanner:
    """
    A class to scan files, directories, and network traffic dumps for exposed API keys and secrets.
    """

    def __init__(self, target, file_types=None, regex_patterns=None, exclude_paths=None):
        """
        Initializes the APIKeyScanner.

        Args:
            target (str): The target path (file, directory, or network traffic dump).
            file_types (list, optional): List of file extensions to scan. Defaults to None (all files).
            regex_patterns (list, optional): List of regex patterns to use for key detection. Defaults to common patterns.
            exclude_paths (list, optional): List of paths to exclude from the scan. Defaults to None.
        """

        self.target = target
        self.file_types = file_types
        self.regex_patterns = regex_patterns or self._default_regex_patterns()  # Use default patterns if none provided
        self.exclude_paths = exclude_paths or []

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
            r"(?i)AKIA[0-9A-Z]{16}",  # AWS API Key
            r"(?i)secret_key=[\"']?[0-9a-zA-Z+/=]{40}[\"']?",  # Secret key
            r"(?i)api_key=[\"']?[0-9a-zA-Z]{32}[\"']?", # Generic API Key with 32 chars
            r"(?i)api_key=[\"']?[0-9a-zA-Z]{40}[\"']?", # Generic API Key with 40 chars
            r"(?i)API_KEY=[\"']?[0-9a-zA-Z]{32}[\"']?", # Generic API Key with 32 chars - uppercase
            r"(?i)API_KEY=[\"']?[0-9a-zA-Z]{40}[\"']?", # Generic API Key with 40 chars - uppercase
            r"(?i)-----BEGIN RSA PRIVATE KEY-----", # RSA Private Key
            r"(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----", # PGP Private Key
            r"(?i)-----BEGIN OPENSSH PRIVATE KEY-----", # OpenSSH Private Key
            r"sk-[a-zA-Z0-9]{32,}",  # OpenAI API keys
            r"AIzaSy[a-zA-Z0-9_-]{35}", # Google Cloud API Key
            r"[a-zA-Z0-9_-]{32}.[a-zA-Z0-9_-]{59}", # Firebase JWT secret
            r"xoxb-[0-9]{11}-[0-9]{12}", # Slack Bot Token
            r"ghp_[a-zA-Z0-9]{36}", # GitHub Personal Access Token
        ]

    def scan_file(self, file_path):
        """
        Scans a single file for API keys and secrets.

        Args:
            file_path (str): The path to the file.

        Returns:
            list: A list of tuples, where each tuple contains the line number and the matched string.
        """

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            logging.error(f"File not found: {file_path}")
            return []
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return []

        matches = []
        for i, line in enumerate(lines):
            for pattern in self.regex_patterns:
                match = re.search(pattern, line)
                if match:
                    matches.append((i + 1, match.group(0).strip()))  # Line number and matched string
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
        for root, _, files in os.walk(directory_path):
            # Exclude specified paths
            if any(os.path.join(root, x).startswith(os.path.abspath(exclude_path)) for exclude_path in self.exclude_paths):
                logging.debug(f"Skipping excluded path: {root}")
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
        Scans a network traffic dump (e.g., PCAP file) for API keys and secrets.
        This is a placeholder and requires specialized libraries like dpkt or scapy to process network packets.

        Args:
            traffic_file_path (str): The path to the network traffic dump file.

        Returns:
            dict: A dictionary where keys are packet numbers and values are lists of matches (matched string).
                   Returns an empty dictionary if the functionality is not fully implemented.
        """
        logging.warning("Network traffic scanning is a placeholder and requires further implementation.")
        logging.warning("You need to implement packet parsing and content analysis using libraries like dpkt or scapy.")
        # In a real implementation, you would:
        # 1. Parse the PCAP file using dpkt or scapy
        # 2. Iterate through each packet
        # 3. Extract the payload (HTTP requests/responses, etc.)
        # 4. Apply the regex patterns to the payload
        # 5. Store the results in a dictionary

        return {} # Placeholder return.

    def scan(self):
        """
        Scans the target (file, directory, or network traffic dump) for API keys and secrets.

        Returns:
            dict: Results of the scan.  The structure depends on the target type.
        """
        try:
            if os.path.isfile(self.target):
                logging.info(f"Scanning file: {self.target}")
                results = {self.target: self.scan_file(self.target)}
            elif os.path.isdir(self.target):
                logging.info(f"Scanning directory: {self.target}")
                results = self.scan_directory(self.target)
            else:
                logging.error(f"Target is not a valid file or directory: {self.target}")
                return {}

            return results

        except Exception as e:
            logging.error(f"An error occurred during the scan: {e}")
            return {}

def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(description="Scans files, directories, or network traffic dumps for exposed API keys and secrets.")
    parser.add_argument("target", help="The target file, directory, or network traffic dump to scan.")
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

        if results:
            print("Scan results:")
            for file_path, matches in results.items():
                if matches:
                    print(f"  File: {file_path}")
                    for line_number, match in matches:
                        print(f"    Line {line_number}: {match}")
                else:
                    logging.debug(f"No matches found in {file_path}") # Only log if verbose mode enabled.
        else:
            print("No API keys or secrets found.")

        # Output to file if specified
        if args.output:
            try:
                with open(args.output, 'w') as outfile:
                    json.dump(results, outfile, indent=4)
                print(f"Results written to {args.output}")
            except Exception as e:
                logging.error(f"Error writing results to file: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
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