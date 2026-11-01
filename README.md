# vuln-API-Key-Exposure-Scanner
Scans local files and directories, such as a codebase or configuration files, for accidentally exposed API keys and secrets. It reads local files only and sends nothing anywhere. It does not scan network traffic or traffic dumps.

Matched values are never printed or written in clear. Reports give the file, line, pattern name, and a masked preview only. A missing target or a failed scan exits non-zero and issues no clean verdict. The clean verdict is printed only after at least one file was actually read.

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-api-key-exposure-scanner`

## Usage
`./vuln-api-key-exposure-scanner [params]`

## Parameters
- `-h`: Show help message and exit
- `target`: The local file or directory to scan (positional, required)
- `-f`: List of file extensions to scan (for example .txt .py .js)
- `-e`: List of paths to exclude from the scan (directories)
- `-o`: Output file to write results to (JSON format, masked values only)
- `-v`: Enable verbose logging
- `-p`: List of custom regex patterns to use for key detection. Use with caution!

## License
Copyright (c) ShadowStrikeHQ
