# PyIntruder CLI - A Powerful Command Line Web Fuzzing Tool
![Asset 2](https://user-images.githubusercontent.com/52795867/141934444-230c8d6e-aee6-4471-883a-2165642e0bbf.png)

PyIntruder CLI is a powerful command-line web fuzzing and penetration testing tool designed for security professionals, bug bounty hunters, and security researchers. It offers high-speed request capabilities in a lightweight command-line package.

![demo2](https://github.com/user-attachments/assets/6aba69a7-7520-4fa4-91c3-6a2c13e7fb10)

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
- **Multi-Position Fuzzing**: Fuzz multiple positions simultaneously with different payload sources

### Advanced Capabilities
- **Payload Encoding**: Support for Base64, Hex, and ASCII Number encoding
- **Custom Headers**: Add and modify request headers
- **JSON Output**: Save results in structured format for further analysis
- **Verbose Mode**: Detailed output for debugging and analysis
- **Request File Support**: Load complex requests from files
- **Flexible Position Markers**: Use custom position markers or default `$p$`

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

## Multi-Position Fuzzing

PyIntruder CLI v1.2.0+ supports fuzzing multiple positions simultaneously, each with different payload sources. There are two ways to use multi-position fuzzing:

### Method 1: Using Numbered Positions ($p1$, $p2$, etc.) - **RECOMMENDED**

This method uses familiar `$p$` markers with numbers, making it intuitive and easy to understand:

1. **Simple username/password fuzzing:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/login?user=$p1$&pass=$p2$' \
     -p1 w:/path/to/usernames.txt \
     -p2 w:/path/to/passwords.txt
   ```

2. **Mix different attack types:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/api?user=$p1$&id=$p2$&token=$p3$' \
     -p1 w:/path/to/users.txt \
     -p2 n:1-1000-1 \
     -p3 b:0123456789abcdef:8:12
   ```

3. **POST request with multiple positions:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/login' -X POST \
     -d 'username=$p1$&password=$p2$&csrf_token=$p3$' \
     -p1 w:/path/to/usernames.txt \
     -p2 w:/path/to/passwords.txt \
     -p3 w:/path/to/tokens.txt
   ```

4. **Headers and URL fuzzing:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/api/$p1$' \
     -H 'Authorization: Bearer $p2$' \
     -p1 w:/path/to/endpoints.txt \
     -p2 w:/path/to/tokens.txt
   ```

5. **Up to 5 positions supported:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/test?a=$p1$&b=$p2$&c=$p3$&d=$p4$&e=$p5$' \
     -p1 w:list1.txt -p2 w:list2.txt -p3 n:1-10-1 -p4 b:abc:1:2 -p5 w:list5.txt
   ```

### Method 2: Using Custom Markers (-mp)

For advanced users who prefer custom marker names:

1. **Multi-position with different wordlists:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/login?user=USER_POS&pass=PASS_POS' \
     -mp USER_POS w:/path/to/usernames.txt \
     -mp PASS_POS w:/path/to/passwords.txt
   ```

2. **Mix wordlist and numeric fuzzing:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/api?user=USER_HERE&id=ID_HERE' \
     -mp USER_HERE w:/path/to/users.txt \
     -mp ID_HERE n:1-1000-1
   ```

3. **Multi-position with different attack types:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/search?q=QUERY&type=TYPE&len=LEN' \
     -mp QUERY w:/path/to/queries.txt \
     -mp TYPE w:/path/to/types.txt \
     -mp LEN n:1-10-1
   ```

4. **POST request with multiple positions:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/login' -X POST \
     -d 'username=USER_VAL&password=PASS_VAL&token=TOKEN_VAL' \
     -mp USER_VAL w:/path/to/usernames.txt \
     -mp PASS_VAL w:/path/to/passwords.txt \
     -mp TOKEN_VAL b:0123456789abcdef:4:8
   ```

5. **Headers and URL multi-position fuzzing:**
   ```bash
   python3 pyintruder_cli.py -u 'http://example.com/api/ENDPOINT' \
     -H 'Authorization: Bearer TOKEN_HERE' \
     -mp ENDPOINT w:/path/to/endpoints.txt \
     -mp TOKEN_HERE w:/path/to/tokens.txt
   ```

**Multi-Position Configuration Formats:**
- **Wordlist**: `w:wordlist.txt`
- **Numbers**: `n:START-END-STEP` (e.g., `n:1-100-1`)
- **Bruteforce**: `b:CHARSET:MIN:MAX` (e.g., `b:abc123:2:4`)

**Comparison of Both Methods:**
```bash
# Method 1: Numbered positions (RECOMMENDED - easier to read)
python3 pyintruder_cli.py -u 'http://example.com/login?user=$p1$&pass=$p2$' \
  -p1 w:usernames.txt -p2 w:passwords.txt

# Method 2: Custom markers (for advanced users)
python3 pyintruder_cli.py -u 'http://example.com/login?user=USER&pass=PASS' \
  -mp USER w:usernames.txt -mp PASS w:passwords.txt
```

**Note**: Multi-position fuzzing generates all combinations of payloads. Be cautious with large payload sets as this can result in many requests (e.g., 100 usernames × 100 passwords = 10,000 requests).

For more advanced usage options, run: `python3 pyintruder_cli.py --help`

## Use Cases

- **API Testing**: Identify vulnerabilities in API endpoints
- **Credential Stuffing**: Test login forms against known username/password lists
- **Parameter Fuzzing**: Discover hidden parameters and injection points
- **Rate Limiting Tests**: Assess application resilience to high request rates
- **Multi-Parameter Testing**: Test multiple parameters simultaneously with different payloads
- **Authentication Bypass**: Test various authentication combinations
- **Input Validation Testing**: Test different input types across multiple fields

## Credits
PyIntruder CLI (2025) is designed and developed by Sagnik Haldar (hsagnik), Swarup Natukula and Nandan Gupta as a complete CLI redesign of the original ![PyIntruder](https://github.com/Yash114Bansal/PyIntruder), which was created by Yash Bansal and Sagnik Haldar in 2021.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Future Enhancements
Grouping the responses by response length and display the count.
