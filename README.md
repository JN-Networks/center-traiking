# Web Security Auditing Tool

This Python script is designed for security professionals and penetration testers. It provides a range of security checks for web applications and servers to assess potential vulnerabilities. The tool covers various security tests, such as subdomain takeover detection, HTTP header security, SSL certificate validation, and more.

## Features

1. **Subdomain Takeover Check**  
   Detects potential subdomain takeover vulnerabilities.

2. **Port Scanner**  
   Scans for open ports on the target server.

3. **HTTP Header Security Check**  
   Analyzes HTTP headers for security misconfigurations.

4. **Whois & DNS Info**  
   Retrieves domain registration details and DNS information.

5. **Directory Bruteforce**  
   Attempts to brute-force directories on the target server.

6. **SSL Certificate Check**  
   Validates the SSL certificate of the target server.

7. **Open Redirect Checker**  
   Identifies open redirect vulnerabilities.

8. **CORS Misconfiguration Checker**  
   Scans for potential CORS misconfigurations.

9. **Tech Detection**  
   Identifies technologies used by the target server.

10. **HTTP Method Checker**  
   Verifies the available HTTP methods on the target server.

11. **DNS Zone Transfer Check**  
   Checks if a DNS zone transfer is possible.

12. **Banner Grabbing**  
   Gathers information about the services running on open ports.

13. **Email & SPF/DMARC Check**  
   Verifies email security settings including SPF and DMARC.

14. **Threat Intelligence Check**  
   Performs threat intelligence lookups related to the target domain.

## Installation

To use this tool, clone this repository and install the required dependencies:

```bash
git clone https://github.com/JN-Networks/center-traiking.git
cd center-traiking
./install.sh
