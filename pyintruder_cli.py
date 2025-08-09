#!/usr/bin/env python3
"""
PyIntruder CLI - A Powerful Command Line Web Fuzzing Tool

Copyright (C) 2023-2025 PyIntruder-CLI team
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
        self.position_marker = "$p$"  # Default position marker changed to $p$
        self.replacement_marker = "@@@@@@"  # Temporary marker for replacement
        self.count = 0
        
        # Multi-position support
        self.multi_position = False
        self.position_configs = []  # List of position configurations
        self.combined_payloads = []  # Combined payload for multi-position attacks
    
    def display_banner(self):
        """Display a pure ASCII banner with copyright information"""
        current_year = datetime.now().year
        version = "1.2.1"  # Updated version: patch version increase for numbered position markers
        
        banner = f"""
{Fore.CYAN}        ______       _____       _                  _            
        | ___ \\     |_   _|     | |                | |           
        | |_/ /   _   | | _ __  | |_ _ __ _   _  __| | ___ _ __ 
        |  __/ | | |  | || '_ \\ | __| '__| | | |/ _` |/ _ \\ '__|
        | |  | |_| | _| || | | || |_| |  | |_| | (_| |  __/ |   
        \\_|   \\__, | \\___/_| |_| \\__|_|   \\__,_|\\__,_|\\___|_|   
               __/ |                                            
              |___/                                             

+-----------[ PyIntruder CLI - A Powerful Intruder ]-----------+
|                                                              |
|  Version: {version}                Author: PyIntruder-CLI team   |
|  Mode: CLI                                                   |
|  License: MIT                                                |
|                    Copyright © 2023-{current_year}                     |
+--------------------------------------------------------------+{Style.RESET_ALL}
"""
        print(banner)

    def parse_arguments(self):
        """Parse command line arguments"""
        # Display the banner before parsing arguments
        self.display_banner()
        
        parser = argparse.ArgumentParser(description='PyIntruder CLI - A Powerful Intruder')
        
        # Attack type selection
        attack_group = parser.add_argument_group('Attack Type (required, choose one)')
        attack = attack_group.add_mutually_exclusive_group(required=False)
        attack.add_argument('-w', '--wordlist', help='Path to wordlist file')
        attack.add_argument('-n', '--numbers', help='Range of numbers in format START-END-STEP')
        attack.add_argument('-b', '--bruteforce', help='Bruteforce with charset in format CHARSET:MIN_LEN:MAX_LEN')
        attack.add_argument('-mp', '--multi-position', action='append', nargs=2, metavar=('MARKER', 'CONFIG'),
                           help='Multi-position fuzzing: MARKER CONFIG. '
                                'CONFIG format: w:wordlist.txt, n:1-100-1, or b:chars:1:3. '
                                'Can be used multiple times for different positions.')
        
        # Numbered position support (alternative to -mp) - separate group
        multi_group = parser.add_argument_group('Multi-Position using $p1$, $p2$, etc. (alternative to -mp)')
        multi_group.add_argument('-p1', '--position1', help='Position 1 config for $p1$: w:wordlist.txt, n:1-100-1, or b:chars:1:3')
        multi_group.add_argument('-p2', '--position2', help='Position 2 config for $p2$: w:wordlist.txt, n:1-100-1, or b:chars:1:3')
        multi_group.add_argument('-p3', '--position3', help='Position 3 config for $p3$: w:wordlist.txt, n:1-100-1, or b:chars:1:3')
        multi_group.add_argument('-p4', '--position4', help='Position 4 config for $p4$: w:wordlist.txt, n:1-100-1, or b:chars:1:3')
        multi_group.add_argument('-p5', '--position5', help='Position 5 config for $p5$: w:wordlist.txt, n:1-100-1, or b:chars:1:3')
        
        # Request related arguments
        req_group = parser.add_argument_group('Request Options')
        req_group.add_argument('-r', '--request-file', help='File containing the HTTP request')
        req_group.add_argument('-u', '--url', help='Target URL (with $p$ as the position marker)')
        req_group.add_argument('-X', '--method', choices=['GET', 'POST'], help='HTTP method')
        req_group.add_argument('-d', '--data', help='POST data (with $p$ as position marker)')
        req_group.add_argument('-H', '--header', action='append', help='HTTP header in format "Name: Value"')
        req_group.add_argument('-m', '--marker', default='$p$', help='Custom position marker (default: $p$)')
        
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
        
        # Check for multi-position mode
        if args.multi_position:
            self.multi_position = True
            self.parse_multi_position_config(args.multi_position)
        
        # Check for numbered position mode
        numbered_positions = []
        for i in range(1, 6):  # Support p1 through p5
            pos_arg = getattr(args, f'position{i}', None)
            if pos_arg:
                numbered_positions.append((f'$p{i}$', pos_arg))
        
        if numbered_positions:
            if self.multi_position:
                print('Error: Cannot use both -mp and -p1/-p2/etc. Choose one method.')
                sys.exit(1)
            self.multi_position = True
            self.parse_multi_position_config(numbered_positions)
        
        # Check if we have any attack type specified
        has_attack_type = (args.wordlist or args.numbers or args.bruteforce or 
                          args.multi_position or numbered_positions)
        
        if not has_attack_type:
            parser.error('Must specify an attack type: -w, -n, -b, -mp, or -p1/-p2/etc.')
        
        # Process the arguments
        if args.request_file:
            self.parse_request_file(args.request_file)
        else:
            if not args.url:
                parser.error('Either --request-file or --url is required')
            
            self.url = args.url
            self.request_method = args.method if args.method else 'GET'
            self.data = args.data if args.data else ''
            
            if args.header:
                for header in args.header:
                    name, value = header.split(':', 1)
                    self.headers[name.strip()] = value.strip()
        
        # Attack type (only for single-position mode)
        if not self.multi_position:
            if args.wordlist:
                self.attack_type = 'Wordlist'
                self.wordlist_filename = args.wordlist
            elif args.numbers:
                self.attack_type = 'Numbers'
                parts = args.numbers.split('-')
                if len(parts) >= 2:
                    self.from_numbers = int(parts[0])
                    self.to_numbers = int(parts[1])
                    self.step_numbers = int(parts[2]) if len(parts) > 2 else 1
            elif args.bruteforce:
                self.attack_type = 'BruteForce'
                parts = args.bruteforce.split(':')
                if len(parts) != 3:
                    parser.error('Bruteforce format should be CHARSET:MIN:MAX')
                self.bruteforce_charset = parts[0]
                self.min_length = int(parts[1])
                self.max_length = int(parts[2])
        
        # Processing options
        self.url_encode = args.url_encode
        self.encoding_type = args.encoding if args.encoding else 'None'
        self.prefix = args.prefix if args.prefix else ''
        self.suffix = args.suffix if args.suffix else ''
        self.option = 2 if args.encode_after else 1
        
        # Output and execution
        self.threads = args.threads
        self.output_file = args.output
        self.verbose = args.verbose
        self.show_headers = args.show_headers
        
        # Set position marker
        self.position_marker = args.marker
        
        # Validate that we have position markers
        if not self.multi_position:
            has_position = False
            if self.position_marker in self.url:
                has_position = True
            if self.position_marker in self.data:
                has_position = True
            for header_name in self.headers:
                if self.position_marker in self.headers[header_name]:
                    has_position = True
                    break
                    
            if not has_position:
                parser.error(f'No position marker ({self.position_marker}) found in the request')
        else:
            # Validate multi-position markers
            self.validate_multi_position_markers()
            
        # Process positions
        self.process_positions()
    
    def parse_request_file(self, filename):
        """Parse an HTTP request from a file"""
        try:
            with open(filename, 'r') as f:
                lines = [line.rstrip("\n") for line in f.readlines()]
                
            # Remove empty lines from the beginning and find the first line
            while lines and not lines[0].strip():
                lines.pop(0)
                
            if not lines:
                raise ValueError("Empty request file")
                
            # First line contains method and path
            first_line = lines[0].split()
            if len(first_line) < 2:
                raise ValueError("Invalid request line format")
                
            self.request_method = first_line[0]
            path = first_line[1]
            
            # Find headers section and data section
            header_end = len(lines)
            data_start = len(lines)
            host = ""
            is_https = False
            
            # Parse headers
            for i in range(1, len(lines)):
                line = lines[i]
                if not line.strip():  # Empty line indicates end of headers
                    header_end = i
                    data_start = i + 1
                    break
                    
                if line.lower().startswith("host:"):
                    host = line[5:].strip()
                
                # Check for HTTPS indicators
                if any(indicator in line.lower() for indicator in ['https://', 'secure', 'ssl']):
                    is_https = True
                
                # Add the header
                header_parts = line.split(':', 1)
                if len(header_parts) == 2:
                    self.headers[header_parts[0].strip()] = header_parts[1].strip()
            
            # Determine protocol (check for HTTPS indicators)
            protocol = "https" if is_https else "http"
            
            # Handle GET requests
            if self.request_method == "GET":
                path_parts = path.split('?')
                clean_path = path_parts[0]
                if len(path_parts) > 1:
                    self.data = path_parts[1]
                else:
                    self.data = ""
                self.url = f"{protocol}://{host}{clean_path}"
            
            # Handle POST requests
            elif self.request_method == "POST":
                self.url = f"{protocol}://{host}{path}"
                
                # Get the POST data
                if data_start < len(lines):
                    # Combine all data lines (in case POST data spans multiple lines)
                    post_data_lines = []
                    for i in range(data_start, len(lines)):
                        if lines[i].strip():  # Only add non-empty lines
                            post_data_lines.append(lines[i])
                    self.data = '\n'.join(post_data_lines) if post_data_lines else ""
                else:
                    self.data = ""
            
            else:
                raise ValueError(f"Unsupported request method: {self.request_method}")
            
            # Debug output to help troubleshoot
            if not host:
                raise ValueError("No Host header found in request")
                
        except Exception as e:
            print(f"Error parsing request file: {e}")
            print(f"Make sure the request file has the correct format:")
            print(f"- First line: METHOD /path HTTP/1.1")
            print(f"- Headers: Name: Value")
            print(f"- Empty line")
            print(f"- POST data (if applicable)")
            sys.exit(1)
    
    def process_positions(self):
        """Process position markers in the request"""
        if self.multi_position:
            # Replace multi-position markers
            for config in self.position_configs:
                marker = config['marker']
                replacement = config['replacement_marker']
                
                # Replace in URL
                if marker in self.url:
                    self.url = self.url.replace(marker, replacement)
                    
                # Replace in data
                if marker in self.data:
                    self.data = self.data.replace(marker, replacement)
                    
                # Replace in headers
                for header_name in self.headers:
                    if marker in self.headers[header_name]:
                        self.headers[header_name] = self.headers[header_name].replace(marker, replacement)
        else:
            # Single position mode - use original logic
            # Replace position markers in URL
            if self.position_marker in self.url:
                self.url = self.url.replace(self.position_marker, self.replacement_marker)
                
            # Replace position markers in data
            if self.position_marker in self.data:
                self.data = self.data.replace(self.position_marker, self.replacement_marker)
                
            # Replace position markers in headers
            for header_name in self.headers:
                if self.position_marker in self.headers[header_name]:
                    self.headers[header_name] = self.headers[header_name].replace(self.position_marker, self.replacement_marker)
    
    def prepare_payloads(self):
        """Prepare the payloads based on the attack type"""
        if self.multi_position:
            # Multi-position mode: generate combinations
            self.prepare_multi_position_payloads()
        else:
            # Single position mode: use original logic
            if self.attack_type == 'Numbers':
                self.payload_list = [x for x in range(self.from_numbers, self.to_numbers + 1, self.step_numbers)]
                print(f'[*] Generated {len(self.payload_list)} number payloads from {self.from_numbers} to {self.to_numbers}')
                
            elif self.attack_type == 'Wordlist':
                try:
                    with open(self.wordlist_filename, 'r', errors='ignore') as f:
                        self.payload_list = [line.rstrip('\n') for line in f]
                    print(f'[*] Loaded {len(self.payload_list)} payloads from wordlist')
                except Exception as e:
                    print(f'Error loading wordlist: {e}')
                    sys.exit(1)
                    
            elif self.attack_type == 'BruteForce':
                self.payload_list = []
                total_combinations = 0
                for x in range(self.min_length, self.max_length + 1):
                    total_combinations += len(self.bruteforce_charset) ** x
                    
                print(f'[*] Generating {total_combinations} bruteforce combinations...')
                
                # Generate combinations (this can be memory intensive for large charsets/lengths)
                for x in range(self.min_length, self.max_length + 1):
                    for y in product(self.bruteforce_charset, repeat=x):
                        self.payload_list.append(''.join(y))
                        
                print(f'[*] Generated {len(self.payload_list)} bruteforce payloads')
    
    def prepare_multi_position_payloads(self):
        """Prepare payload combinations for multi-position fuzzing"""
        # Get all payload lists
        payload_lists = [config['payloads'] for config in self.position_configs]
        
        # Calculate total combinations
        total_combinations = 1
        for payloads in payload_lists:
            total_combinations *= len(payloads)
            
        print(f'[*] Multi-position mode: {len(self.position_configs)} positions')
        for i, config in enumerate(self.position_configs):
            print(f'    Position {i+1} ({config["marker"]}): {config["type"]} - {len(config["payloads"])} payloads')
        print(f'[*] Total combinations: {total_combinations}')
        
        if total_combinations > 100000:
            print(f'[!] Warning: {total_combinations} combinations will be generated. This may take a long time!')
            response = input('Continue? (y/N): ')
            if response.lower() != 'y':
                print('[*] Aborted by user')
                sys.exit(0)
        
        # Generate all combinations
        self.combined_payloads = list(product(*payload_lists))
        print(f'[*] Generated {len(self.combined_payloads)} payload combinations')
    
    def process_payload(self, payload):
        """Process a single payload with encoding options"""
        payload = str(payload)
        
        # Apply prefix/suffix before encoding or encoding before prefix/suffix
        if self.option == 1:  # Suffix/Prefix -> Encode
            temp_payload = f'{self.prefix}{payload}{self.suffix}'
            
            if self.encoding_type == 'Base64':
                temp_payload = b64encode(temp_payload.encode()).decode()
            elif self.encoding_type == 'Hex':
                temp_payload = hexlify(temp_payload.encode()).decode()
            elif self.encoding_type == 'ASCII':
                temp_payload = ''.join(str(ord(c)) for c in temp_payload)
                
            return temp_payload
        else:  # Encode -> Suffix/Prefix
            temp_payload = payload
            
            if self.encoding_type == 'Base64':
                temp_payload = b64encode(temp_payload.encode()).decode()
            elif self.encoding_type == 'Hex':
                temp_payload = hexlify(temp_payload.encode()).decode()
            elif self.encoding_type == 'ASCII':
                temp_payload = ''.join(str(ord(c)) for c in temp_payload)
                
            return f'{self.prefix}{temp_payload}{self.suffix}'
    
    def send_request(self, payload):
        """Send a single request with the given payload"""
        if self.multi_position:
            # Multi-position mode: payload is a tuple of payloads
            return self.send_multi_position_request(payload)
        else:
            # Single position mode: use original logic
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
                if self.request_method == 'GET':
                    r = requests.get(url, params=data, headers=headers)
                else:  # POST
                    r = requests.post(url, data=data, headers=headers)
                    
                # Store the result
                status_desc = STATUS_CODES.get(str(r.status_code), 'UNKNOWN')
                self.results[str(payload)] = [
                    str(len(r.text)),
                    f'{r.status_code} {status_desc}',
                    r.text
                ]
                
                # If we're storing response headers, add them
                if self.show_headers:
                    self.results[str(payload)].append(dict(r.headers))
                
                self.count += 1
                
                # Print progress if verbose
                if self.verbose:
                    print(f'[{self.count}/{len(self.payload_list)}] Payload: {payload} | Length: {len(r.text)} | Status: {r.status_code} {status_desc}')
                else:
                    # Print a simple progress indicator
                    sys.stdout.write(f'\r[*] Progress: {self.count}/{len(self.payload_list)} requests')
                    sys.stdout.flush()
                    
            except Exception as e:
                print(f'\nError processing payload \'{payload}\': {e}')
    
    def send_multi_position_request(self, payload_combination):
        """Send a request with multiple position payloads"""
        # payload_combination is a tuple like ('payload1', 'payload2', ...)
        
        # Start with the original request components
        url = self.url
        data = self.data
        headers = {}
        for header_name in self.headers:
            headers[header_name] = self.headers[header_name]
        
        # Replace each position with its corresponding payload
        for i, (config, payload) in enumerate(zip(self.position_configs, payload_combination)):
            processed_payload = self.process_payload(payload)
            replacement_marker = config['replacement_marker']
            
            # Replace in URL, data, and headers
            url = url.replace(replacement_marker, processed_payload)
            data = data.replace(replacement_marker, processed_payload)
            for header_name in headers:
                headers[header_name] = headers[header_name].replace(replacement_marker, processed_payload)
        
        # URL encode if needed
        if self.url_encode:
            data = quote(data, safe='')
        
        try:
            if self.request_method == 'GET':
                r = requests.get(url, params=data, headers=headers)
            else:  # POST
                r = requests.post(url, data=data, headers=headers)
                
            # Store the result with combination as key
            status_desc = STATUS_CODES.get(str(r.status_code), 'UNKNOWN')
            combination_key = ' | '.join([f'{config["marker"]}:{payload}' for config, payload in zip(self.position_configs, payload_combination)])
            
            self.results[combination_key] = [
                str(len(r.text)),
                f'{r.status_code} {status_desc}',
                r.text
            ]
            
            # If we're storing response headers, add them
            if self.show_headers:
                self.results[combination_key].append(dict(r.headers))
            
            self.count += 1
            
            # Print progress if verbose
            if self.verbose:
                print(f'[{self.count}/{len(self.combined_payloads)}] Payloads: {combination_key} | Length: {len(r.text)} | Status: {r.status_code} {status_desc}')
            else:
                # Print a simple progress indicator
                sys.stdout.write(f'\r[*] Progress: {self.count}/{len(self.combined_payloads)} requests')
                sys.stdout.flush()
                
        except Exception as e:
            print(f'\nError processing payload combination \'{combination_key}\': {e}')
    
    def run_attack(self):
        """Run the attack with multiple threads"""
        if self.multi_position:
            attack_type = 'Multi-Position'
            total_payloads = len(self.combined_payloads)
            payload_source = self.combined_payloads
        else:
            attack_type = self.attack_type
            total_payloads = len(self.payload_list)
            payload_source = self.payload_list
            
        print(f'[*] Starting {attack_type} attack with {self.threads} threads...')
        print(f'[*] Target: {self.url}')
        print(f'[*] Method: {self.request_method}')
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.send_request, payload_source)
            
        print(f'\n[+] Attack complete. {self.count} requests sent.')
        
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
        
        print('\n--- Results Summary ---')
        if self.multi_position:
            print(f'Total payload combinations: {len(self.combined_payloads)}')
        else:
            print(f'Total payloads: {len(self.payload_list)}')
        print(f'Total responses: {len(self.results)}')
        print('\nStatus Code Distribution:')
        for status in sorted(status_counts.keys()):
            print(f'  {status}: {status_counts[status]}')
            
        # Group by response length
        length_counts = {}
        for payload in self.results:
            length = self.results[payload][0]
            if length in length_counts:
                length_counts[length] += 1
            else:
                length_counts[length] = 1
                
        print('\nResponse Length Distribution:')
        # Show top 5 most common lengths
        sorted_lengths = sorted(length_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        for length, count in sorted_lengths:
            print(f'  Length {length}: {count} responses')
            
        print('\n--- Notable Responses ---')
        # Show some interesting payloads (e.g., non-200 responses or unusual lengths)
        shown_responses = 0
        
        # First show non-200 responses (up to 5)
        for payload in self.results:
            if '200' not in self.results[payload][1] and shown_responses < 5:
                status = self.results[payload][1]
                length = self.results[payload][0]
                if self.multi_position:
                    print(f'  Combination: {payload}')
                else:
                    print(f'  Payload: {payload}')
                print(f'    Status: {status}')
                print(f'    Length: {length}')
                shown_responses += 1
                
        # If we haven't shown 5 yet, show responses with unusual lengths
        if shown_responses < 5:
            # Find the most common length
            most_common_length = sorted_lengths[0][0] if sorted_lengths else None
            
            for payload in self.results:
                if self.results[payload][0] != most_common_length and shown_responses < 5:
                    status = self.results[payload][1]
                    length = self.results[payload][0]
                    if self.multi_position:
                        print(f'  Combination: {payload}')
                    else:
                        print(f'  Payload: {payload}')
                    print(f'    Status: {status}')
                    print(f'    Length: {length}')
                    shown_responses += 1
    
    def save_results(self):
        """Save the results to a JSON file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.results, f)
            print(f'[+] Results saved to {self.output_file}')
        except Exception as e:
            print(f'Error saving results: {e}')

    def parse_multi_position_config(self, multi_position_args):
        """Parse multi-position configuration"""
        for marker, config in multi_position_args:
            position_config = {
                'marker': marker,
                'replacement_marker': f'@@@@{len(self.position_configs)}@@@@',
                'payloads': []
            }
            
            # Parse config string
            if config.startswith('w:'):
                # Wordlist: w:wordlist.txt
                wordlist_file = config[2:]
                try:
                    with open(wordlist_file, 'r', errors='ignore') as f:
                        position_config['payloads'] = [line.rstrip('\n') for line in f]
                    position_config['type'] = 'Wordlist'
                    position_config['source'] = wordlist_file
                except Exception as e:
                    print(f'Error loading wordlist {wordlist_file}: {e}')
                    sys.exit(1)
                    
            elif config.startswith('n:'):
                # Numbers: n:1-100-1
                numbers_config = config[2:]
                parts = numbers_config.split('-')
                if len(parts) >= 2:
                    start = int(parts[0])
                    end = int(parts[1])
                    step = int(parts[2]) if len(parts) > 2 else 1
                    position_config['payloads'] = list(range(start, end + 1, step))
                    position_config['type'] = 'Numbers'
                    position_config['source'] = f'{start}-{end}-{step}'
                else:
                    print(f'Invalid numbers format for position {marker}. Use n:START-END-STEP')
                    sys.exit(1)
                    
            elif config.startswith('b:'):
                # Bruteforce: b:charset:min:max
                bf_parts = config[2:].split(':')
                if len(bf_parts) == 3:
                    charset, min_len, max_len = bf_parts[0], int(bf_parts[1]), int(bf_parts[2])
                    position_config['payloads'] = []
                    for length in range(min_len, max_len + 1):
                        for combo in product(charset, repeat=length):
                            position_config['payloads'].append(''.join(combo))
                    position_config['type'] = 'BruteForce'
                    position_config['source'] = f'{charset}:{min_len}:{max_len}'
                else:
                    print(f'Invalid bruteforce format for position {marker}. Use b:CHARSET:MIN:MAX')
                    sys.exit(1)
            else:
                print(f'Invalid config format for position {marker}. Use w:file, n:start-end-step, or b:charset:min:max')
                sys.exit(1)
                
            self.position_configs.append(position_config)
            print(f'[*] Position {marker}: {position_config["type"]} with {len(position_config["payloads"])} payloads')
    
    def validate_multi_position_markers(self):
        """Validate that all defined position markers exist in the request"""
        for config in self.position_configs:
            marker = config['marker']
            found = False
            
            if marker in self.url:
                found = True
            if marker in self.data:
                found = True
            for header_name in self.headers:
                if marker in self.headers[header_name]:
                    found = True
                    break
                    
            if not found:
                print(f'Error: Position marker "{marker}" not found in the request')
                sys.exit(1)
    
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
        print('\n[!] Attack interrupted by user')
        sys.exit(0)