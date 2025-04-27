# Multi-threaded HTTP Web Server

A lightweight, multi-threaded HTTP web server implemented in Python that can handle multiple client requests simultaneously.

## Features

- Multi-threaded architecture for handling concurrent connections
- Support for HTTP/1.1 with keep-alive connections
- Handles GET and HEAD request methods
- Automatic MIME type detection for served files
- Proper handling of conditional requests (If-Modified-Since)
- Common Log Format (CLF) logging
- Path traversal protection
- Automatic port selection if default port is in use

## Requirements

- Python 3.10+
- No external dependencies required (uses only standard library modules)

## Usage

### Starting the Server

```bash
python network.py [port] [document_root]
