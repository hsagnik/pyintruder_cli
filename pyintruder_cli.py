#!/usr/bin/env python3
"""
PyIntruder CLI - A Powerful Command Line Web Fuzzing Tool

Copyright (C) 2023-2025 hsagnik
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import argparse
import requests
import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from base64 import b64encode
from binascii import hexlify
from itertools import product
from urllib.parse import quote
from colorama import init, Fore, Style
from datetime import datetime

# Initialize colorama for cross-platform terminal colors
init()

# HTTP Status Codes - Same as GUI version
STATUS_CODES = {
    "100": "CONTINUE", "101": "SWITCHING_PROTOCOLS", "200": "OK", "201": "CREATED",
    "202": "ACCEPTED", "203": "NON_AUTHORITATIVE_INFORMATION", "204": "NO_CONTENT",
    "205": "RESET_CONTENT", "206": "PARTIAL_CONTENT", "207": "MULTI_STATUS",
    "208": "ALREADY_REPORTED", "226": "IM_USED", "300": "MULTIPLE_CHOICES",
    "301": "MOVED_PERMANENTLY", "302": "FOUND", "303": "SEE_OTHER",
    "304": "NOT_MODIFIED", "305": "USE_PROXY", "306": "RESERVED",
    "307": "TEMPORARY_REDIRECT", "308": "PERMANENT_REDIRECT", "400": "BAD_REQUEST",
    "401": "UNAUTHORIZED", "402": "PAYMENT_REQUIRED", "403": "FORBIDDEN",
    "404": "NOT_FOUND", "405": "METHOD_NOT_ALLOWED", "406": "NOT_ACCEPTABLE",
    "407": "PROXY_AUTHENTICATION_REQUIRED", "408": "REQUEST_TIMEOUT", "409": "CONFLICT",
    "410": "GONE", "411": "LENGTH_REQUIRED", "412": "PRECONDITION_FAILED",
    "413": "REQUEST_ENTITY_TOO_LARGE", "414": "REQUEST_URI_TOO_LONG",
    "415": "UNSUPPORTED_MEDIA_TYPE", "416": "REQUESTED_RANGE_NOT_SATISFIAB",
    "417": "EXPECTATION_FAILED", "418": "IM_A_TEAPOT", "422": "UNPROCESSABLE_ENTITY",
    "423": "LOCKED", "424": "FAILED_DEPENDENCY", "426": "UPGRADE_REQUIRED",
    "428": "PRECONDITION_REQUIRED", "429": "TOO_MANY_REQUESTS",
    "431": "REQUEST_HEADER_FIELDS_TOO_LARGE", "451": "UNAVAILABLE_FOR_LEGAL_REASONS",
    "500": "INTERNAL_SERVER_ERROR", "501": "NOT_IMPLEMENTED", "502": "BAD_GATEWAY",
    "503": "SERVICE_UNAVAILABLE", "504": "GATEWAY_TIMEOUT",
    "505": "VERSION_NOT_SUPPORTED", "506": "VARIANT_ALSO_NEGOTIATES",
    "507": "INSUFFICIENT_STORAGE", "508": "LOOP_DETECTED",
    "509": "BANDWIDTH_LIMIT_EXCEEDED", "510": "NOT_EXTENDED",
    "511": "NETWORK_AUTHENTICATION_REQUIRED"
}

class PyIntruderCLI:
    def __init__(self):
        self.url = ""
        self.data = ""
        self.headers = {}
        self.request_method = ""
        self.from_numbers = 0
        self.to_numbers = 0
        self.step_numbers = 1
        self.min_length = 1
        self.max_length = 1
        self.bruteforce_charset = ""
        self.wordlist_filename = ""
        self.url_encode = False
        self.encoding_type = "None"  # None, Base64, Hex, ASCII Numbers
        self.prefix = ""
        self.suffix = ""
        self.option = 1  # 1: Suffix/Prefix -> Encode, 2: Encode -> Suffix/Prefix
        self.payload_list = []
        self.results = {}
        self.threads = 10
        self.verbose = False
        self.attack_type = ""
        self.position_marker = "§§"  # Double § as position marker (like GUI)
        self.replacement_marker = "@@@@@@"  # Temporary marker for replacement
        self.count = 0
    
    def display_banner(self):
        """Display a pure ASCII banner with copyright information"""
        current_year = datetime.now().year
        version = "1.0.0"  # Initial release version
        
        banner = f"""
{Fore.CYAN}        ______       _____       _                  _            
        | ___ \     |_   _|     | |                | |           
        | |_/ /   _   | | _ __  | |_ _ __ _   _  __| | ___ _ __ 
        |  __/ | | |  | || '_ \ | __| '__| | | |/ _` |/ _ \ '__|
        | |  | |_| | _| || | | || |_| |  | |_| | (_| |  __/ |   
        \_|   \__, | \___/_| |_| \__|_|   \__,_|\__,_|\___|_|   
               __/ |                                            
              |___/                                             

+-----------[ PyIntruder CLI - A Powerful Intruder ]-----------+
|                                                              |
|  Version: {version}                        Author: hsagnik       |
|  Mode: CLI                                                   |
|  License: GNU GPL v3                                         |
|                    Copyright © 2023-{current_year}                     |
+--------------------------------------------------------------+{Style.RESET_ALL}
"""
        print(banner)

    def parse_arguments(self):
        """Parse command line arguments"""
        # Display the banner before parsing arguments
        self.display_banner()
        
        parser = argparse.ArgumentParser(description="PyIntruder CLI - A Powerful Intruder")
        
        # Attack type selection
        attack_group = parser.add_argument_group('Attack Type (required, choose one)')
        attack = attack_group.add_mutually_exclusive_group(required=True)
        attack.add_argument('-w', '--wordlist', help='Path to wordlist file')
        attack.add_argument('-n', '--numbers', help='Range of numbers in format START-END-STEP')
        attack.add_argument('-b', '--bruteforce', help='Bruteforce with charset in format CHARSET:MIN_LEN:MAX_LEN')
        
        # Request related arguments
        req_group = parser.add_argument_group('Request Options')
        req_group.add_argument('-r', '--request-file', help='File containing the HTTP request')
        req_group.add_argument('-u', '--url', help='Target URL (with §§ as the position marker)')
        req_group.add_argument('-X', '--method', choices=['GET', 'POST'], help='HTTP method')
        req_group.add_argument('-d', '--data', help='POST data (with §§ as position marker)')
        req_group.add_argument('-H', '--header', action='append', help='HTTP header in format "Name: Value"')
        
        # Payload processing options
        proc_group = parser.add_argument_group('Payload Processing')
        proc_group.add_argument('--url-encode', action='store_true', help='URL encode the payload')
        proc_group.add_argument('--encoding', choices=['Base64', 'Hex', 'ASCII'], help='Encode the payload')
        proc_group.add_argument('--prefix', help='Prefix to add to each payload')
        proc_group.add_argument('--suffix', help='Suffix to add to each payload')
        proc_group.add_argument('--encode-after', action='store_true', 
                               help='Apply encoding after prefix/suffix (default is before)')
        
        # Output and execution options
        out_group = parser.add_argument_group('Output and Execution')
        out_group.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
        out_group.add_argument('-o', '--output', help='Output file for results (JSON format)')
        out_group.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        out_group.add_argument('--show-headers', action='store_true', help='Show response headers in output')
                
        args = parser.parse_args()
        
        # Process the arguments
        if args.request_file:
            self.parse_request_file(args.request_file)
        else:
            if not args.url:
                parser.error("Either --request-file or --url is required")
            
            self.url = args.url
            self.request_method = args.method if args.method else "GET"
            self.data = args.data if args.data else ""
            
            if args.header:
                for header in args.header:
                    name, value = header.split(':', 1)
                    self.headers[name.strip()] = value.strip()
        
        # Attack type
        if args.wordlist:
            self.attack_type = "Wordlist"
            self.wordlist_filename = args.wordlist
        elif args.numbers:
            self.attack_type = "Numbers"
            parts = args.numbers.split('-')
            if len(parts) >= 2:
                self.from_numbers = int(parts[0])
                self.to_numbers = int(parts[1])
                self.step_numbers = int(parts[2]) if len(parts) > 2 else 1
        elif args.bruteforce:
            self.attack_type = "BruteForce"
            parts = args.bruteforce.split(':')
            if len(parts) != 3:
                parser.error("Bruteforce format should be CHARSET:MIN:MAX")
            self.bruteforce_charset = parts[0]
            self.min_length = int(parts[1])
            self.max_length = int(parts[2])
        
        # Processing options
        self.url_encode = args.url_encode
        self.encoding_type = args.encoding if args.encoding else "None"
        self.prefix = args.prefix if args.prefix else ""
        self.suffix = args.suffix if args.suffix else ""
        self.option = 2 if args.encode_after else 1
        
        # Output and execution
        self.threads = args.threads
        self.output_file = args.output
        self.verbose = args.verbose
        self.show_headers = args.show_headers
        
        # Validate that we have position markers
        has_position = False
        if "§§" in self.url:
            has_position = True
        if "§§" in self.data:
            has_position = True
        for header_name in self.headers:
            if "§§" in self.headers[header_name]:
                has_position = True
                break
                
        if not has_position:
            parser.error("No position marker (§§) found in the request")
            
        # Process positions
        self.process_positions()
    
    def parse_request_file(self, filename):
        """Parse an HTTP request from a file"""
        try:
            with open(filename, 'r') as f:
                lines = [line.rstrip("\n") for line in f.readlines() if line.strip()]
                
            # First line contains method and path
            first_line = lines[0].split()
            self.request_method = first_line[0]
            
            # Extract URL and data for GET requests
            if self.request_method == "GET":
                path_parts = first_line[1].split('?')
                path = path_parts[0]
                if len(path_parts) > 1:
                    self.data = path_parts[1]
                
                # Get the host from the headers to build the full URL
                host = ""
                for i in range(1, len(lines)):
                    if lines[i].lower().startswith("host:"):
                        host = lines[i][5:].strip()
                        break
                
                self.url = f"http://{host}{path}"
            
            # Extract headers and data for POST requests
            elif self.request_method == "POST":
                path = first_line[1]
                
                # Get the host and other headers
                data_start = 0
                host = ""
                for i in range(1, len(lines)):
                    if not lines[i].strip():
                        data_start = i + 1
                        break
                    
                    if lines[i].lower().startswith("host:"):
                        host = lines[i][5:].strip()
                    
                    # Add the header
                    header_parts = lines[i].split(':', 1)
                    if len(header_parts) == 2:
                        self.headers[header_parts[0].strip()] = header_parts[1].strip()
                
                self.url = f"http://{host}{path}"
                
                # Get the data if it exists
                if data_start > 0 and data_start < len(lines):
                    self.data = lines[data_start]
            
            else:
                raise ValueError(f"Unsupported request method: {self.request_method}")
                
        except Exception as e:
            print(f"Error parsing request file: {e}")
            sys.exit(1)
    
    def process_positions(self):
        """Process position markers in the request"""
        # Replace position markers in URL
        if "§§" in self.url:
            self.url = self.url.replace("§§", self.replacement_marker)
            
        # Replace position markers in data
        if "§§" in self.data:
            self.data = self.data.replace("§§", self.replacement_marker)
            
        # Replace position markers in headers
        for header_name in self.headers:
            if "§§" in self.headers[header_name]:
                self.headers[header_name] = self.headers[header_name].replace("§§", self.replacement_marker)
    
    def prepare_payloads(self):
        """Prepare the payloads based on the attack type"""
        if self.attack_type == "Numbers":
            self.payload_list = [x for x in range(self.from_numbers, self.to_numbers + 1, self.step_numbers)]
            print(f"[*] Generated {len(self.payload_list)} number payloads from {self.from_numbers} to {self.to_numbers}")
            
        elif self.attack_type == "Wordlist":
            try:
                with open(self.wordlist_filename, 'r', errors='ignore') as f:
                    self.payload_list = [line.rstrip('\n') for line in f]
                print(f"[*] Loaded {len(self.payload_list)} payloads from wordlist")
            except Exception as e:
                print(f"Error loading wordlist: {e}")
                sys.exit(1)
                
        elif self.attack_type == "BruteForce":
            self.payload_list = []
            total_combinations = 0
            for x in range(self.min_length, self.max_length + 1):
                total_combinations += len(self.bruteforce_charset) ** x
                
            print(f"[*] Generating {total_combinations} bruteforce combinations...")
            
            # Generate combinations (this can be memory intensive for large charsets/lengths)
            for x in range(self.min_length, self.max_length + 1):
                for y in product(self.bruteforce_charset, repeat=x):
                    self.payload_list.append("".join(y))
                    
            print(f"[*] Generated {len(self.payload_list)} bruteforce payloads")
    
    def process_payload(self, payload):
        """Process a single payload with encoding options"""
        payload = str(payload)
        
        # Apply prefix/suffix before encoding or encoding before prefix/suffix
        if self.option == 1:  # Suffix/Prefix -> Encode
            temp_payload = f"{self.prefix}{payload}{self.suffix}"
            
            if self.encoding_type == "Base64":
                temp_payload = b64encode(temp_payload.encode()).decode()
            elif self.encoding_type == "Hex":
                temp_payload = hexlify(temp_payload.encode()).decode()
            elif self.encoding_type == "ASCII":
                temp_payload = ''.join(str(ord(c)) for c in temp_payload)
                
            return temp_payload
        else:  # Encode -> Suffix/Prefix
            temp_payload = payload
            
            if self.encoding_type == "Base64":
                temp_payload = b64encode(temp_payload.encode()).decode()
            elif self.encoding_type == "Hex":
                temp_payload = hexlify(temp_payload.encode()).decode()
            elif self.encoding_type == "ASCII":
                temp_payload = ''.join(str(ord(c)) for c in temp_payload)
                
            return f"{self.prefix}{temp_payload}{self.suffix}"
    
    def send_request(self, payload):
        """Send a single request with the given payload"""
        processed_payload = self.process_payload(payload)
        
        # Replace the placeholder with the processed payload
        url = self.url.replace(self.replacement_marker, processed_payload)
        data = self.data.replace(self.replacement_marker, processed_payload)
        
        # URL encode if needed
        if self.url_encode:
            data = quote(data, safe='')
        
        # Replace in headers
        headers = {}
        for header_name in self.headers:
            headers[header_name] = self.headers[header_name].replace(
                self.replacement_marker, processed_payload)
        
        try:
            if self.request_method == "GET":
                r = requests.get(url, params=data, headers=headers)
            else:  # POST
                r = requests.post(url, data=data, headers=headers)
                
            # Store the result
            status_desc = STATUS_CODES.get(str(r.status_code), "UNKNOWN")
            self.results[str(payload)] = [
                str(len(r.text)),
                f"{r.status_code} {status_desc}",
                r.text
            ]
            
            # If we're storing response headers, add them
            if self.show_headers:
                self.results[str(payload)].append(dict(r.headers))
            
            self.count += 1
            
            # Print progress if verbose
            if self.verbose:
                print(f"[{self.count}/{len(self.payload_list)}] Payload: {payload} | Length: {len(r.text)} | Status: {r.status_code} {status_desc}")
            else:
                # Print a simple progress indicator
                sys.stdout.write(f"\r[*] Progress: {self.count}/{len(self.payload_list)} requests")
                sys.stdout.flush()
                
        except Exception as e:
            print(f"\nError processing payload '{payload}': {e}")
    
    def run_attack(self):
        """Run the attack with multiple threads"""
        print(f"[*] Starting {self.attack_type} attack with {self.threads} threads...")
        print(f"[*] Target: {self.url}")
        print(f"[*] Method: {self.request_method}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.send_request, self.payload_list)
            
        print(f"\n[+] Attack complete. {self.count} requests sent.")
        
        # Print a summary of the results
        self.print_summary()
        
        # Save results if output file specified
        if hasattr(self, 'output_file') and self.output_file:
            self.save_results()
    
    def print_summary(self):
        """Print a summary of the results"""
        # Group by status code
        status_counts = {}
        for payload in self.results:
            status = self.results[payload][1]
            if status in status_counts:
                status_counts[status] += 1
            else:
                status_counts[status] = 1
        
        print("\n--- Results Summary ---")
        print(f"Total payloads: {len(self.payload_list)}")
        print(f"Total responses: {len(self.results)}")
        print("\nStatus Code Distribution:")
        for status in sorted(status_counts.keys()):
            print(f"  {status}: {status_counts[status]}")
            
        # Group by response length
        length_counts = {}
        for payload in self.results:
            length = self.results[payload][0]
            if length in length_counts:
                length_counts[length] += 1
            else:
                length_counts[length] = 1
                
        print("\nResponse Length Distribution:")
        # Show top 5 most common lengths
        sorted_lengths = sorted(length_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for length, count in sorted_lengths:
            print(f"  Length {length}: {count} responses")
            
        print("\n--- Notable Responses ---")
        # Show some interesting payloads (e.g., non-200 responses or unusual lengths)
        shown_responses = 0
        
        # First show non-200 responses (up to 5)
        for payload in self.results:
            if "200" not in self.results[payload][1] and shown_responses < 5:
                status = self.results[payload][1]
                length = self.results[payload][0]
                print(f"  Payload: {payload}")
                print(f"    Status: {status}")
                print(f"    Length: {length}")
                shown_responses += 1
                
        # If we haven't shown 5 yet, show responses with unusual lengths
        if shown_responses < 5:
            # Find the most common length
            most_common_length = sorted_lengths[0][0] if sorted_lengths else None
            
            for payload in self.results:
                if self.results[payload][0] != most_common_length and shown_responses < 5:
                    status = self.results[payload][1]
                    length = self.results[payload][0]
                    print(f"  Payload: {payload}")
                    print(f"    Status: {status}")
                    print(f"    Length: {length}")
                    shown_responses += 1
    
    def save_results(self):
        """Save the results to a JSON file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f)
            print(f"[+] Results saved to {self.output_file}")
        except Exception as e:
            print(f"Error saving results: {e}")

    def run(self):
        """Main execution function"""
        self.parse_arguments()
        self.prepare_payloads()
        self.run_attack()

if __name__ == "__main__":
    try:
        cli = PyIntruderCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        sys.exit(0)