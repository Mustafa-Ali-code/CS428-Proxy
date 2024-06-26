# Web Proxy Server

## Description
This project implements a sequential and a concurrent web proxy servers. The proxy accepts HTTP GET and HEAD requests,
forwards them to the intended servers, and logs each request. It supports modifying HTTP/1.1 requests to HTTP/1.0 before
forwarding and can handle requests in parallel through multithreading to efficiently manage multiple simultaneous connections.

## Features
- **Concurrency**: Utilizes threads to handle multiple client requests concurrently.
- **HTTP Protocol Handling**: Modifies HTTP/1.1 requests to HTTP/1.0 for compatibility with older web servers.
- **Blocklist Functionality**: Blocks requests to URLs specified in a blocklist, enhancing security and compliance.
- **Logging**: Logs detailed information about each request including the client IP, requested URL, and size of the response.
- **Robust Error Handling**: Provides error messages to the client for various error conditions like blocked URLs, not found, bad requests, etc.

## Testing
### Methodology
The proxy was tested using a variety of methods to ensure functionality, stability, and concurrency:
- **Functional Testing**: Tested the basic functionality using `curl` to make requests through the proxy.
- **Concurrency Testing**: Multiple simultaneous requests were sent using `curl` in separate terminal windows and with scripts to ensure that the proxy handles concurrency appropriately.
- **Blocklist Testing**: Specific URLs were added to the blocklist to verify that the proxy correctly blocks those requests and logs the attempts.
- **Logging Verification**: Checked the log file to ensure that every request and its details were logged accurately.
- **Error Handling**: Deliberately made requests that would result in errors (e.g., requesting non-existent pages) to verify that the proxy returns appropriate error messages.

### Results
The proxy server successfully handled all tested scenarios:
- Concurrent requests were managed without any loss of data or crashes.
- Requests to URLs in the blocklist were consistently blocked, and the correct HTTP status code (403 Forbidden) was returned.
- The log entries were correctly formatted and included all necessary information, confirming the reliability of the logging mechanism.
- The proxy was robust in handling erroneous requests.
