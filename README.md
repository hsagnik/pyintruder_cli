# PyIntruder CLI - A Powerful Command Line Web Fuzzing Tool
![Asset 2](https://user-images.githubusercontent.com/52795867/141934444-230c8d6e-aee6-4471-883a-2165642e0bbf.png)

PyIntruder CLI is a powerful command-line web fuzzing and penetration testing tool designed for security professionals, bug bounty hunters, and security researchers. It offers high-speed request capabilities in a lightweight command-line package.

## Installation
```bash
git clone https://github.com/hsagnik/pyintruder_cli
cd pyintruder_cli
pip install -r requirements.txt
```

## Features

### Efficient Fuzzing
- **Multi-threaded Architecture**: Send hundreds of requests per second
- **Low Resource Consumption**: Optimized for performance on modest hardware
- **Scriptable Interface**: Perfect for integration with other tools and automation workflows

### Comprehensive Attack Methods
- **Wordlist Support**: Use your favorite wordlists for payload testing
- **Numeric Sequence Generation**: Generate numeric payloads on the fly
- **Character Set Bruteforce**: Custom character set bruteforcing with configurable length 

### Advanced Capabilities
- **Payload Encoding**: Support for Base64, Hex, and ASCII Number encoding
- **Custom Headers**: Add and modify request headers
- **JSON Output**: Save results in structured format for further analysis
- **Verbose Mode**: Detailed output for debugging and analysis
- **Request File Support**: Load complex requests from files

## Usage

PyIntruder CLI uses the symbol `$p$` to mark the position for payload insertion in URLs, request bodies, or headers.

### Basic Examples:

1. **Wordlist attack against a login form:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/login?user=$p$' -w /path/to/usernames.txt
   ```

2. **Numeric fuzzing with 10 threads:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/products?id=$p$' -n 1-100 -t 10
   ```

3. **POST request with password testing:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/login' -X POST -d 'username=admin&password=$p$' -w /path/to/passwords.txt
   ```

4. **Using a request file (easier for complex requests):**
   ```bash
   python3 pyintruder_cli.py -r request.txt -w /path/to/payloads.txt
   ```
   
   Where request.txt contains something like:
   ```
   POST /api/login HTTP/1.1
   Host: example.com
   Content-Type: application/json
   
   {"username": "admin", "password": "$p$"}
   ```

5. **Bruteforce with custom character set:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/login?pin=$p$' -b 'abcdefghijklmnopqrstuvwxyz:1:3'
   ```

6. **Adding Base64 encoding to payloads:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/api?data=$p$' -w /path/to/payloads.txt --encoding Base64
   ```

7. **Save results to a JSON file:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/login?user=$p$' -w /path/to/usernames.txt -o results.json -v
   ```

8. **Using custom headers with a position marker:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/api' -X GET -H 'Authorization: Bearer $p$' -w /path/to/tokens.txt
   ```

9. **Adding prefix and suffix to payloads:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/search?q=$p$' -w /path/to/keywords.txt --prefix 'search+' --suffix '*'
   ```

10. **URL-encoding payloads with special characters:**
    ```bash
    python3 pyintruder_cli.py -u 'http://example.com/search?q=$p$' -w /path/to/special_chars.txt --url-encode
    ```

11. **Using a custom position marker:**
    ```bash
    python3 pyintruder_cli.py -u 'http://example.com/search?q=INJECT_HERE' -m 'INJECT_HERE' -w /path/to/payloads.txt
    ```

For more advanced usage options, run: `python3 pyintruder_cli.py --help`

## Use Cases

- **API Testing**: Identify vulnerabilities in API endpoints
- **Credential Stuffing**: Test login forms against known username/password lists
- **Parameter Fuzzing**: Discover hidden parameters and injection points
- **Rate Limiting Tests**: Assess application resilience to high request rates

## Credits
PyIntruder CLI (2025) is designed and developed by Sagnik Haldar (hsagnik) as a complete CLI redesign of the original ![PyIntruder](https://github.com/Yash114Bansal/PyIntruder), which was created by Yash Bansal and Sagnik Haldar in 2021.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

