# path-finder

**path-finder** is a command-line tool designed to help identify payloads that can be used to exploit **Path Traversal** vulnerabilities in web applications.

## Maintainer
[dg0mezm](https://www.linkedin.com/in/dg0mezm/)

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Usage](#usage)
- [Arguments](#arguments)
- [Disclaimer](#disclaimer)

## Overview
Path Traversal vulnerabilities allow attackers to access files and directories that are stored outside the web root folder. This tool helps automate the process of testing various payloads against a target endpoint to detect potential vulnerabilities.

## Features
- Automatic testing of common and custom path traversal payloads
- Multi-threaded request engine for fast execution
- Response filtering by size
- Depth control for payload length
- Customizable timeout settings

## Example of Usage

Example usage for testing the path `/image` with the `filename` parameter, while filtering the response size to exclude `14` and `30`:
```
python path-finder.py --target https://0a5f000804d44f0883c1c81f00fb00fb.web-security-academy.net/ --path /image --param filename --fs 14,30
```

## Arguments
| Argument | Description |
| --- | --- |
| `--target` | Specify the target's URL or IP address (required) |
| `--path` | Specify the path within the target website (required) |
| `--param` | Specify the name of the parameter to test (required) |
| `--depth` | Set the maximum depth level to test (default: 4) |
| `--fs` | Filter responses by size. Provide one or more sizes separated by commas (e.g., 50,85) |
| `--threads` | Specify the number of threads to use for concurrent requests (default: 20) |
| `--timeout` | Set the timeout duration (in seconds) for each request (default: 5) |

## Disclaimer
This tool is intended for educational purposes and authorized testing only. Use it responsibly and only on systems you have permission to test. The author assumes no liability for any misuse.