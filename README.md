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

## Functions
- Multi-threaded Web server
- Proper request and response message exchanges
- GET command for both text files and image files
- HEAD command
- Four types of response statuses
-- 200 OK
-- 400 Bad Request
-- 404 File Not Found
-- 304 Not Modified
-- 415 Unspupported Media Type
-- 401 Forbidden
- Last-Modified and If-Modified-Since header fields
- Keep-Alive header field

## Requirements

- Python 3.10+
- No external dependencies required (uses only standard library modules)

## Usage

### Starting the Server

-Put the website source files into folder - ./www

```bash
python network.py [port] [document_root]
