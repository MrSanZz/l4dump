import os
try:
    import time, datetime, psutil, ssl
    import ctypes, sys, random, socket, struct
    from terminaltables import AsciiTable
    from scapy.all import *
    import platform as pf
    import itertools
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    from os.path import exists
    import subprocess
    import re
    import platform
    import threading
    import socks
    from stem import Signal
    from stem.control import Controller
    import select
    import warnings
except ModuleNotFoundError as e:
    filter = str(e).replace("No module named", '').replace("'", '')
    print(f"Installing module : {filter}")
    os.system(f'python3 -m pip install {filter}')
warnings.filterwarnings("ignore")
sys.stderr = open(os.devnull, "w")

previous_proxy = None

def supports_connect(proxy_host, proxy_port):
    try:
        test_sock = socket.create_connection((proxy_host, int(proxy_port)), timeout=5)
        connect_cmd = b"CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"
        test_sock.sendall(connect_cmd)
        resp = test_sock.recv(4096)
        return b"200 Connection established" in resp
    except Exception:
        return False

chain_proxies = [
    "47.236.163.74:8080", "138.68.60.8:8080", "194.170.146.125:8080",
    "13.212.95.135:8000", "18.102.219.234:80", "13.112.30.61:80"
]
chain_proxies = [proxy for proxy in chain_proxies if supports_connect(*proxy.split(':'))]

current_chain_proxy = [random.choice(chain_proxies)]

def start_proxy(local_ip, local_port, proxy_ip, proxy_port):
    def handle_client(client_socket):
        try:
            proxy = socks.socksocket()
            proxy.connect((proxy_ip, proxy_port))

            while True:
                r, _, _ = select.select([client_socket, proxy], [], [])
                if client_socket in r:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    proxy.sendall(data)
                if proxy in r:
                    response = proxy.recv(4096)
                    if not response:
                        break
                    client_socket.sendall(response)
        finally:
            client_socket.close()
            proxy.close()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((local_ip, local_port))
    server.listen(5)
    print(f"Listening on {local_ip}:{local_port}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

def start_tor_proxy():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)

    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket

local_ip = "127.0.0.1"
local_port = 8080

def get_mac_address(ip_address):
    if platform.system() == "Windows":
        command = f"arp -a {ip_address}"
    else:
        command = f"arp -a {ip_address}"

    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    mac_address = re.search(r"(\w{2}[:-]\w{2}[:-]\w{2}[:-]\w{2}[:-]\w{2}[:-]\w{2})", result.stdout)

    if mac_address:
        return mac_address.group(1)
    else:
        return '00:00:00:00:00'

def generate_self_signed_cert(cert_file="server.crt", key_file="server.key"):
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Java"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Internet"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "JogjaXploit"),
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("127.0.0.1")]), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    with open(key_file, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Generated self-signed certificate: {cert_file}, {key_file}")

colors = {
    "first": '\033[0m',
    "second": '\033[0m'
}

class color:
    def red():
        return '\033[1;91m'

import socks

def detect_proxy_type(ip, port, timeout=5):
    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, ip, int(port))
        s.settimeout(timeout)
        s.connect(("1.1.1.1", 80))
        s.close()
        return "SOCKS5"
    except:
        pass

    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS4, ip, int(port))
        s.settimeout(timeout)
        s.connect(("1.1.1.1", 80))
        s.close()
        return "SOCKS4"
    except:
        pass

    try:
        s = socket.create_connection((ip, int(port)), timeout)
        s.sendall(b"CONNECT www.google.com:80 HTTP/1.1\r\nHost: www.google.com\r\n\r\n")
        response = s.recv(4096)
        if b"200 Connection established" in response:
            s.close()
            return "HTTP"
        s.close()
    except:
        pass

    try:
        s = socket.create_connection((ip, int(port)), timeout)
        s.close()
        return "TCP"
    except:
        pass

    return "UNKNOWN"

class proxy:
    def proxy_logger():
        PROXY_HOST = '127.0.0.1'
        PROXY_PORT = 8080
        DNS = input(f"{colors['second']}[{colors['first']}Optional{colors['second']}] {colors['first']}DNS Server [ e.g 1.1.1.1:1.0.0.1 ]: ")
        if DNS:
            DNS_SERVERS = [(DNS.split(':')[0], 53), (DNS.split(':')[1], 53)]
        else:
            DNS_SERVERS = [('1.1.1.1', 53), ('1.0.0.1', 53)]
        print(F"{colors['second']}[{colors['first']}Optional{colors['second']}] {colors['first']}e.g: id.pinterest.com,www.youtube.com,192.168.1.1,172.16.16.1")
        blocked_site = input(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Block address: ").split(',')
        blocked_site = [site.strip() for site in blocked_site if site.strip()]
        if blocked_site:
            blocked_site = blocked_site
        else:
            blocked_site = []
        print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Blocked: {blocked_site}")

        def resolve_domain(domain, port):
            try:
                for dns_server in DNS_SERVERS:
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns_socket:
                            dns_socket.settimeout(2)
                            dns_socket.connect(dns_server)
                            dns_socket.sendall(build_dns_query(domain))
                            response = dns_socket.recv(512)
                            ip_address = extract_ip_from_response(response)
                            return f"{ip_address}:{port}"
                    except Exception as e:
                        continue
                ip_address = socket.gethostbyname(domain)
                return f"{ip_address}:{port}"
            except socket.gaierror as e:
                return f"{color.red()}[{colors['first']}+{color.red()}] {colors['first']}Error: {e}"

        def build_dns_query(domain):
            header = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            question = b''.join((len(part).to_bytes(1, 'big') + part.encode() for part in domain.split('.')))
            question += b'\x00\x00\x01\x00\x01'
            return header + question

        def extract_ip_from_response(response):
            if response[3] == 0:
                return socket.inet_ntoa(response[-4:])
            raise Exception("Invalid DNS Response")

        def is_blocked(address):
            if not blocked_site or blocked_site == ['']:
                return False
            return any(blocked in address for blocked in blocked_site)

        def handle_http(client_socket):
            request = client_socket.recv(65536).decode()

            first_line = request.split("\n")[0]
            method = first_line.split(" ")[0]
            addr = first_line.split(" ")[1].split(":")[0]

            if is_blocked(addr):
                client_socket.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                client_socket.close()
                print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}Blocked HTTP access from {addr}")
                return

            if method == "CONNECT":
                try:
                    host_port = first_line.split(" ")[1]
                    host, port = host_port.split(":")
                    port = int(port)

                    remote_socket = socket.create_connection((host, port))
                    client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

                    relay_data(client_socket, remote_socket)
                    handle_tcp(client_socket, host, port)

                    if host:
                        print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}Connected address: "+str(host)+':'+str(port)+" Method: "+str(method))
                        print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}Client requests: "+str(first_line))
                        print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}Headers: ")
                        print(request)
                        resolved_address = resolve_domain(addr, port)
                        print(f"{colors['second']}[{colors['first']}RESOLVED{colors['second']}] {colors['first']}{resolved_address}")
                    else:
                        pass

                except Exception as e:
                    print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}HTTP: {e}")
                    client_socket.close()
                return
            else:
                print(f"{colors['second']}[{colors['first']}HTTP-LOG{colors['second']}] {colors['first']}HTTP request: ")
                print(request)
                client_socket.close()

        def udp_associate(client_socket):
            try:
                request = client_socket.recv(262)

                if len(request) < 10:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']} Invalid UDP ASSOCIATE request")
                    client_socket.close()
                    return

                address_type = request[3]

                if address_type == 1:
                    address = socket.inet_ntoa(request[4:8])
                    port = struct.unpack('!H', request[8:10])[0]
                elif address_type == 3:
                    domain_length = request[4]
                    address = request[5:5 + domain_length].decode()
                    port = struct.unpack('!H', request[5 + domain_length:5 + domain_length + 2])[0]
                else:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']} Unsupported address type for UDP")
                    client_socket.close()
                    return

                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}UDP Associate: {address}:{port}")

                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.bind(('0.0.0.0', 0))
                local_port = udp_socket.getsockname()[1]

                response = b"\x05\x00\x00\x01" + socket.inet_aton(PROXY_HOST) + struct.pack('!H', local_port)
                client_socket.sendall(response)

                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}UDP relay aktif di port {local_port}")

                def udp_relay():
                    while True:
                        data, addr = udp_socket.recvfrom(4096)

                        if addr[0] == client_socket.getpeername()[0]:
                            udp_socket.sendto(data[3:], (address, port))
                            print(f"{colors['second']}[{colors['first']}UDP-LOG{colors['second']}] {colors['first']}From Client: {data[3:].hex()}")

                        else:
                            header = b"\x00\x00\x00\x01" + socket.inet_aton(addr[0]) + struct.pack('!H', addr[1])
                            udp_socket.sendto(header + data, client_socket.getpeername())
                            print(f"{colors['second']}[{colors['first']}UDP-LOG{colors['second']}] {colors['first']}From Server: {data.hex()}")

                threading.Thread(target=udp_relay).start()

            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}UDP Associate: {e}")
                client_socket.close()

        def handle_tcp(client_socket, target_host, target_port):
            try:
                proxy_host, proxy_port = current_chain_proxy[0].split(':')
                proxy_port = int(proxy_port)
                remote_socket = socket.create_connection((proxy_host, proxy_port))

                connect_cmd = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
                remote_socket.sendall(connect_cmd.encode())

                response = remote_socket.recv(4096)
                if b"200 Connection established" not in response:
                    print(f"[CHAIN ERROR] Proxy refused connection: {response}")
                    client_socket.close()
                    remote_socket.close()
                    return

                threading.Thread(target=relay_data, args=(client_socket, remote_socket)).start()
                threading.Thread(target=relay_data, args=(remote_socket, client_socket)).start()

            except Exception as e:
                print(f"[ERROR] TCP Chain Proxy failed: {e}")
                client_socket.close()

        def handle_socks5(client_socket):
            handshake = client_socket.recv(2)
            print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Handshake: {handshake}")

            if len(handshake) != 2 or handshake[0] != 5:
                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Invalid SOCKS5 handshake")
                client_socket.close()
                return

            client_socket.sendall(b"\x05\x00")

            request = client_socket.recv(4)
            print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Raw request: {request}")

            try:
                if request[1] == 1:
                    handle_tcp(client_socket, address, port)
                    return

                elif len(request) < 4:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Invalid request length: {len(request)} - {request}")
                    client_socket.close()
                    return

                elif request[0] != 5:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Invalid SOCKS version: {request[0]}")
                    return

                elif request[1] != 1:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Invalid command: {request[1]}")
                    client_socket.close()
                    return

                elif request[1] == 3:
                    print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Handling UDP ASSOCIATE")
                    udp_associate(client_socket)

                address_type = request[3]
                if address_type == 1:
                    address = socket.inet_ntoa(client_socket.recv(4))
                elif address_type == 3:
                    domain_length = client_socket.recv(1)[0]
                    address = client_socket.recv(domain_length).decode()
                else:
                    print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Invalid address type")
                    client_socket.close()
                    return

                port = struct.unpack('!H', client_socket.recv(2))[0]

                if is_blocked(address):
                    print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Blocked address: {address}")
                    client_socket.close()
                    return

            except IndexError as e:
                print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Error: "+str(e))
                pass

            except:
                print(f"{color.red()}[{colors['first']}SOCKS5-LOG{color.red()}] {colors['first']}Error: "+str(e))
                pass

            try:
                remote_socket = socket.create_connection((address, port))
                client_socket.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(address) + struct.pack('!H', port))

                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Connected to {address}:{port}")
                print(f"{colors['second']}[{colors['first']}SOCKS5-LOG{colors['second']}] {colors['first']}Client request: {request}")

                relay_data(client_socket, remote_socket)

            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}SOCKS5: {e}")
                client_socket.close()

        def handle_tls(client_socket, REMOTE_HOST, REMOTE_PORT):
            if is_blocked(REMOTE_HOST):
                print(f"{colors['second']}[{colors['first']}BLOCKED{colors['second']}] {colors['first']}TLS connection to {REMOTE_HOST}")
                client_socket.close()
                return
            try:
                context = ssl.create_default_context()
                remote_socket = socket.create_connection((REMOTE_HOST, REMOTE_PORT))
                remote_socket = context.wrap_socket(remote_socket, server_hostname=REMOTE_HOST)

                def relay_data(source, destination):
                    while True:
                        data = source.recv(4096)
                        if not data:
                            break
                        destination.sendall(data)

                client_to_server = threading.Thread(target=relay_data, args=(client_socket, remote_socket))
                client_to_server.start()

                relay_data(remote_socket, client_socket)

            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']}handle_client: {e}")
            finally:
                client_socket.close()
                remote_socket.close()

        def handle_udp(udp_socket):
            while True:
                data, addr = udp_socket.recvfrom(4096)
                if is_blocked(addr[0]):
                    print(f"{colors['second']}[{colors['first']}BLOCKED{colors['second']}] {colors['first']}UDP from {addr}")
                    continue
                print(f"{colors['second']}[{colors['first']}UDP-LOG{colors['second']}] {colors['first']}Data from {addr}: {data}")

        def relay_data(client_socket, remote_socket):
            start_time = time.time()
            total_bytes = 0
            sockets = [client_socket, remote_socket]
            try:
                while True:
                    if client_socket.fileno() == -1 or remote_socket.fileno() == -1:
                        print(f"{colors['second']}[{colors['first']}LOG{colors['second']}] {colors['first']}Socket closed, exiting relay")
                        break
                    ready_sockets, _, _ = select.select(sockets, [], [])
                    for sock in ready_sockets:
                        if sock.fileno() == -1:
                            print(f"{colors['second']}[{colors['first']}LOG{colors['second']}] {colors['first']}Socket closed during relay")
                            break
                        data = sock.recv(505536)
                        if not data:
                            print(f"{colors['second']}[{colors['first']}LOG{colors['second']}] {colors['first']}Connection closed")
                            client_socket.close()
                            remote_socket.close()
                            return
                        total_bytes += len(data)
                        elapsed_time = time.time() - start_time
                        if total_bytes == 0 or elapsed_time == 0:
                            speed = 0
                        else:
                            speed = total_bytes / elapsed_time / (364 * 366)
                        if sock is client_socket:
                            remote_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                        print(f"{colors['second']}[{colors['first']}LOG{colors['second']}] {colors['first']} Data: " + str(data.hex()[:10]) + f' Speed: {speed:.2f}MB/ps                         ', end='\r')
            except Exception as e:
                print(f"{color.red()}[{colors['first']}ERROR{color.red()}] {colors['first']} relay_data: {e}")

        def start_proxy():
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((PROXY_HOST, PROXY_PORT))
            server.listen(5)

            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind((PROXY_HOST, PROXY_PORT))

            print(f"{colors['second']}[{colors['first']}!{colors['second']}] {colors['first']}Proxy launched on {PROXY_HOST}:{PROXY_PORT}")
            proxy_slots = {
                "http": None,
                "tcp": None,
                "socks5": None,
                "socks4": None,
                "udp": None,
            }

            print("[+] Please wait!. Checking proxy..")

            for address in chain_proxies:
                ip, port = address.split(":")
                detected_type = detect_proxy_type(ip, port)

                if detected_type in proxy_slots:
                    previous_value = proxy_slots[detected_type]
                    proxy_slots[detected_type] = address

                    print(f"[CHAIN] ✅ Slot '{detected_type}' updated from {previous_value} → {address}")
                else:
                    print(f"[CHAIN] ❌ Unknown or unsupported proxy type: {detected_type} - adding")
                    proxy_slots[str(detected_type).lower()] = address

            print("[+] Done, starting proxy service..")

            def rotate_proxy():
                while True:
                    candidate_proxy = random.choice(chain_proxies)
                    ip, port = candidate_proxy.split(":")
                    port = int(port)

                    detected_type = detect_proxy_type(ip, port)

                    if detected_type in proxy_slots:
                        previous_value = proxy_slots[detected_type]
                        proxy_slots[detected_type] = candidate_proxy

                        print(f"[CHAIN] ✅ Slot '{detected_type}' updated from {previous_value} → {candidate_proxy}")
                    else:
                        print(f"[CHAIN] ❌ Unknown or unsupported proxy type: {detected_type} - adding")
                        proxy_slots[str(detected_type).lower()] = candidate_proxy
                    http = proxy_slots['http']
                    sock5 = proxy_slots['socks5']
                    sock4 = proxy_slots['socks4']
                    udp = proxy_slots['udp']
                    tcp = proxy_slots['tcp']
                    if http:
                        ip, port = http.split(':')
                        socks.set_default_proxy(socks.PROXY_TYPE_HTTP, ip, int(port))
                        socket.socket = socks.socksocket
                    if sock5:
                        ip, port = sock5.split(':')
                        socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, ip, int(port))
                        socket.socket = socks.socksocket
                    if sock4:
                        ip, port = sock4.split(':')
                        socks.set_default_proxy(socks.PROXY_TYPE_SOCKS4, ip, int(port))
                        socket.socket = socks.socksocket

                    print(f"[SLOTS] Active proxy map: {proxy_slots}")
                    time.sleep(60)

            threading.Thread(target=handle_udp, args=(udp_socket,)).start()
            threading.Thread(target=rotate_proxy, daemon=True).start()

            while True:
                try:
                    client_socket, addr = server.accept()
                    print(f"{colors['second']}[{colors['first']}+{colors['second']}] {colors['first']}Incoming connections from {addr}", end='\r')

                    first_byte = client_socket.recv(1, socket.MSG_PEEK)
                    if first_byte == b"\x05":  # SOCKS5
                        threading.Thread(target=handle_socks5, args=(client_socket,)).start()
                    elif first_byte == b"\x16":
                        print(f"{colors['second']}[{colors['first']}TLS-LOG{colors['second']}] {colors['first']}Connection request from: "+str(addr))
                        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                        if exists('server.crt') and exists('server.key'):
                            context.load_cert_chain(certfile="server.crt", keyfile="server.key")
                        else:
                            generate_self_signed_cert("server.crt", "server.key")
                            context.load_cert_chain(certfile="server.crt", keyfile="server.key")
                        client_socket = context.wrap_socket(client_socket, server_side=True)
                        request = client_socket.recv(65535).decode()
                        first_line = request.split("\n")[0]
                        host_port = first_line.split(" ")[1]
                        host, port = host_port.split(":")
                        port = int(port)
                        threading.Thread(target=handle_tls, args=(client_socket, host, port)).start()
                    else: # HTTP
                        threading.Thread(target=handle_http, args=(client_socket,)).start()
                except KeyboardInterrupt:
                    print('\nExiting..')
                    break

        if __name__ == '__main__':
            start_proxy()

global source_port, dest_port, os_type, available
available = None
os_type = '1' if os.name == 'posix' else '0'
ip_target = []
source_port = 0
dest_port = 0

def run_as_admin():
    if os_type == 0:
        if ctypes.windll.shell32.IsUserAnAdmin():
            print("Administrator mode detected, running.")
        else:
            print("Requesting Administrator Mode...")
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
    else:
        pass

def clear():
    os.system('clear' if os_type == '1' else 'cls')

def table_print(head, init):
    table_data = [head] + [init]
    table = AsciiTable(table_data)
    print(table.table)

def l4_tls_header():
    header = '\\x'.join(str(random.choice("abc1234567890=-+")*2) + '\\' for _ in range(1, random.randint(70, 500) + 1))
    return header

def l4_tls():
    tls_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    head = l4_tls_header()
    tls_socket.sendto(head, (ip_target, dest_port))

def l4_tcp():
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    global source_port, dest_port
    seq = 1
    ack_seq = 0
    offset_res = (5 << 4) | 0
    flags = 0x02
    window = 8192
    checksum = 0
    urg_ptr = 0

    tcp_header = struct.pack('!HHLLBBHHH',
                        source_port, dest_port, seq, ack_seq, offset_res,
                        flags, window, checksum, urg_ptr)
    tcp_socket.sendto(tcp_header, (ip_target, dest_port))

def l4_udp():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    global source_port, dest_port
    length = 28
    checksum = 0xABCD

    udp_header = struct.pack('!HHHH', source_port, dest_port, length, checksum)
    udp_socket.sendto(udp_header, (ip_target, dest_port))

class execute:
    def scan_network(ip, gway):
        def get_network_info():
            gateways = psutil.net_if_addrs()
            default_gateways = psutil.net_if_stats()
            routes = psutil.net_if_addrs()
            default = psutil.net_if_addrs()
            gateway_info = psutil.net_if_addrs()
            gateway_default = psutil.net_if_stats()

            for iface_name, addresses in gateway_info.items():
                for addr in addresses:
                    if addr.family.name == "AF_INET":
                        if iface_name in gateway_default and gateway_default[iface_name].isup:
                            return iface_name, addr.address
            return None, None, gateways, default_gateways, routes, default

        def scan_network(ip):
            arp = ARP(pdst=ip)
            ether = Ether(dst=get_mac_address(ip))
            packet = ether / arp

            result = srp(packet, timeout=2, verbose=0)[0]

            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
            return devices

        def main(ip, gateway):
            global available
            ifaces, gateways = get_network_info()
            if ifaces and gateways and not ip and not gateway:
                print(f"Interface: {ifaces}")
                print(f"Gateway: {gateways}")

                ip_range = '.'.join(gateways.split('.')[:-1]) + '.1/24'
                print(f"Scanning network: {ip_range}...\n")

                devices = scan_network(ip_range)
                if devices:
                    print("Devices found:")
                    for device in devices:
                        print(f"IP: {device['ip']}, MAC: {device['mac']}")
                        available += device['ip']
                else:
                    print("No device found.\n")
            elif ip and gateway:
                print(f"Interface: {ip}")
                print(f"Gateway: {gateway}")

                ip_range = '.'.join(gateway.split('.')[:-1]) + '.1/24'
                print(f"Scanning network: {ip_range}...\n")

                devices = scan_network(ip_range)
                if devices:
                    print("Devices found:")
                    for device in devices:
                        print(f"IP: {device['ip']}, MAC: {device['mac']}")
                        available += device['ip']
                else:
                    print("No device found.\n")
            else:
                print("Failed to detect the network interface or gateway.")

        if __name__ == "__main__":
            main(ip, gway)

    def get_network_interfaces():
        global available
        interfaces = []
        ipsz = []
        ips = []
        mac = []

        processed_ips = set()

        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == "AF_INET":
                    interfaces.append({"Interface": iface})
                    ipsz.append({"IP Address": addr.address})
                    ips.append(addr.address)
                    mac.append({"Mac Address": next((a.address for a in addrs if a.family.name == "AF_LINK"), "Unknown").replace('-', ':')})

        new_ips = [ip for ip in ips if ip not in processed_ips]
        if new_ips:
            processed_ips.update(new_ips)

        display_ips = new_ips if new_ips else list(processed_ips)

        available = display_ips
        table_data = [['Interface', 'IP Address', 'Mac Address']]
        for i in range(len(interfaces)):
            table_data.append([interfaces[i]['Interface'], ipsz[i]['IP Address'], mac[i]['Mac Address']])

        table = AsciiTable(table_data)
        print(table.table)

    def get_default_gateway():
        iface = []
        gateway = []
        gateways = psutil.net_if_addrs()
        for iface_name, iface_info in psutil.net_if_stats().items():
            if iface_info.isup:
                for addr in gateways.get(iface_name, []):
                    if addr.family.name == "AF_INET":
                        iface.append({"iface": iface_name})
                        gateway.append({"gateway": addr.address})
        table_data = [['Interface', 'Gateway']]
        for i in range(len(iface)):
            table_data.append([iface[i]['iface'], gateway[i]['gateway']])
        table = AsciiTable(table_data)
        print(table.table)
        return None

    def scan_wifi():
        system_os = pf.system()
        SSID = []
        BSSID = []
        SIGNAL = []

        try:
            if system_os == "Windows":
                result = subprocess.check_output(["netsh", "wlan", "show", "networks", "mode=bssid"], text=True)
                networks = result.split("\n")

                ssid = None
                for line in networks:
                    line = line.strip()
                    if line.startswith("SSID "):
                        ssid = line.split(":")[1].strip()
                    elif line.startswith("BSSID "):
                        bssid = line.split(":")[1].strip()
                    elif line.startswith("Signal"):
                        signal = line.split(":")[1].strip()
                        SSID.append({"SSID": ssid})
                        BSSID.append({"BSSID": bssid})
                        SIGNAL.append({"Signal": signal})

            elif system_os == "Linux":
                result = subprocess.check_output(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL", "dev", "wifi"], text=True)
                networks = result.strip().split("\n")
                for network in networks:
                    ssid, bssid, signal = network.split(":")
                    SSID.append({"SSID": ssid})
                    BSSID.append({"BSSID": bssid})
                    SIGNAL.append({"Signal": signal})

            else:
                print("OS not supported for Wi-Fi scanning.")
        except Exception as e:
            print(f"Error scanning Wi-Fi: {e}")

        table_data = [['SSID', 'BSSID', 'Signal Strength']]
        for i in range(len(SSID)):
            table_data.append([SSID[i]['SSID'], BSSID[i]['BSSID'], SIGNAL[i]['Signal']])
        table = AsciiTable(table_data)
        print(table.table)
        return None

    def sniff_network(ip, mac):
        arp = ARP(pdst=ip)
        ether = Ether(dst=mac)
        packet = ether / arp

        result = srp(packet, timeout=2, verbose=0)[0]

        ip = []
        mac = []
        for sent, received in result:
            ip.append({'ip': received.psrc})
            mac.append({'mac': received.hwsrc})
        if ip:
            table_print(ip, mac)
        else:
            table_print(['No results'], ['No results'])
        return None

    def scan_wifi_clients(ip_range, mac):
        try:
            print(f"Scanning network: {ip_range}:{mac}")
            arp = ARP(pdst=ip_range)
            ether = Ether(dst=mac)
            packet = ether / arp
            result = srp(packet, timeout=5, verbose=0)[0]

            clients = []
            for sent, received in result:
                clients.append({'ip': received.psrc, 'mac': received.hwsrc})

            if not clients:
                print("No client detected in {}".format(ip_range))
                return

            print("Connected client in {}:".format(ip_range))
            print("IP Address\tMAC Address")
            print("-" * 40)
            for client in clients:
                print(f"{client['ip']}\t{client['mac']}")
        except KeyboardInterrupt:
            print('\nExiting..')
            return

    def proxy():
        if __name__ == "__main__":
            proxy.proxy_logger()

class tools:
    def main():
        def set_dns_to_cloudflare():
            """Set DNS to Cloudflare's 1.1.1.1"""
            if pf.system() == "Windows":
                os.system("netsh interface ip set dns name=\"Wi-Fi\" static 1.1.1.1")
                os.system("netsh interface ip add dns name=\"Wi-Fi\" 1.0.0.1 index=2")
            elif pf.system() == "Linux":
                resolv_conf = "/etc/resolv.conf"
                with open(resolv_conf, "w") as file:
                    file.write("nameserver 1.1.1.1\nnameserver 1.0.0.1\n")
            else:
                print("OS aren't supported.")

        def flush_dns():
            """Flush DNS cache"""
            if pf.system() == "Windows":
                os.system("ipconfig /flushdns")
            elif pf.system() == "Linux":
                os.system("systemd-resolve --flush-caches")
            else:
                print("OS aren't supported")

        def prioritize_wifi():
            """Prioritize WiFi connection"""
            if pf.system() == "Windows":
                os.system("netsh wlan set profileparameter name=\"Wi-Fi\" connectiontype=ESS")
            else:
                None

        def optimize_wifi():
            """Run all optimization steps"""
            print("Setting DNS to Cloudflare...")
            set_dns_to_cloudflare()
            print("Clearing cache DNS...")
            flush_dns()
            print("Setting net priority WiFi...")
            prioritize_wifi()
            print("Optimization Completed.")

        if __name__ == "__main__":
            optimize_wifi()

class monitor:
    def start():
        def load_history(log_file):
            """Memuat riwayat dari file log."""
            if os.path.exists(log_file):
                with open(log_file, 'r') as file:
                    return json.load(file)
            return []

        def save_log(log_file, data):
            """Menyimpan log ke file."""
            with open(log_file, 'w') as file:
                json.dump(data, file, indent=4)

        def scan_network(ip_range):
            """Memindai perangkat di jaringan WiFi."""
            print(f"Scanning network: {ip_range}")
            arp = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=5, verbose=0)[0]

            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})

            return devices

        def monitor_wifi(ip_range, log_file):
            """Memantau aktivitas WiFi dan menyimpan log."""
            print("\nMemulai monitoring WiFi...")
            log_data = load_history(log_file)
            if log_data:
                print(f"{len(log_data)} log history loaded from {log_file}.")
            else:
                print("No previous log found, starting fresh.")

            try:
                while True:
                    devices = scan_network(ip_range)
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    log_entry = {
                        "timestamp": timestamp,
                        "devices": devices
                    }
                    log_data.append(log_entry)
                    save_log(log_file, log_data)

                    print(f"[{timestamp}] {len(devices)} device(s) detected.")
                    for device in devices:
                        print(f"IP: {device['ip']}, MAC: {device['mac']}")

                    print("\nWaiting 10 seconds before next scan...")
                    time.sleep(10)

            except KeyboardInterrupt:
                print("\nMonitoring stopped by user.")

        if __name__ == "__main__":
            table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
            to_unlock = input("\n[Select IP To Monitor]: ")
            if to_unlock in ip_target:
                IP_RANGE = to_unlock
            LOG_FILE = "log.json"

            monitor_wifi(IP_RANGE, LOG_FILE)

    def mitm():
        from flask import Flask, request, render_template_string
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options

        app = Flask(__name__)

        def render_page(url):
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")

            driver = webdriver.Chrome(options=chrome_options)

            try:
                driver.get(url)
                page_source = driver.page_source
                return page_source
            except Exception as e:
                return f"Error: {e}"
            finally:
                driver.quit()

        @app.route("/")
        def proxy():
            target_url = request.args.get("url")
            if not target_url:
                return "Masukkan URL di query string. Contoh: ?url=https://www.youtube.com"

            html_content = render_page(target_url)
            return render_template_string(html_content)

        if __name__ == "__main__":
            app.run(debug=False, port=8080)


def prompt():
    try:
        username = "netsucker"
    except FileNotFoundError:
        raise ValueError('No user file detected!')
    PS1 = f"┌({username}@root - fsociety)-[~/bin]\n┕━>"
    prompt = input(PS1 + '')
    print('')
    return prompt

class banner:
    def lobby():
        logo = "         ,-.               \n"
        logo += "        / \\\  `.  __..-,O   \n"
        logo += "       :   \\ --''_..-'.'   \n"
        logo += "       |    . .-' `. '.    \n"
        logo += "       :     .     .`.'    \n"
        logo += "        \\     `.  /  ..    \n"
        logo += "         \\      `.   ' .   \n"
        logo += "          `,       `.   \\  \n"
        logo += "         ,|,`.        `-.\\ \n"
        logo += "        '.||  ``-...__..-` \n"
        logo += "         |  |              \n"
        logo += "         |__|              \n"
        logo += "         /||\\              \n"
        logo += "        //||\\\\             \n"
        logo += "       // || \\\\            \n"
        logo += "    __//__||__\\\\\__         \n"
        logo += "   '--------------' SSt    \n"
        logo += "   MrSanZz? Wh0 1s h3>?    \n"
        return logo

if __name__ == "__main__":
    run_as_admin()
    clear()
    print(banner.lobby())
    execute.scan_network(None, None)
    while True:
        option = prompt()
        if option.lower() == 'sniff':
            for ips in ip_target:
                execute.sniff_network(ips, get_mac_address(ips))
        if option.lower() == 'msniff':
            execute.sniff_network(input("[+] IP Address: "), input("[+] MAC target: ").replace('-', ':'))
        elif option.lower() == 'scan':
            execute.scan_wifi()
        elif option.lower() == 'mac':
            print(get_mac_address(input("[+] IP: ")))
        elif option.lower() == 'gateway':
            execute.get_default_gateway()
        elif option.lower() == 'iface':
            execute.get_network_interfaces()
        elif option.lower() == 'netsniff':
            execute.scan_network(input("[+] Interface: "), input("[+] Gateway/IP: "))
        elif option.lower() == 'available':
            try:
                table_print(['Available IP Address'], ['{}'.format('\n'.join(available))])
            except:
                table_print(['Available IP Address'], ['No IP Available, please type iface!'])
        elif option.lower() == 'alock':
            table_print(['Available IP Address'], ['{}'.format('\n'.join(available))])
            ip = input('[Insert IP To Lock]: ')
            ip_target.append(ip)
            table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
        elif option.lower() == 'remv':
            table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
            to_unlock = input("[Select IP To Unlock]: ")
            if to_unlock in ip_target:
                ip_target.remove(to_unlock)
                print(f"Unlocked! - {to_unlock}")
            else:
                print("[!] IP aren't available")
        elif option.lower() == 'locked':
            table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
        elif option.lower() == 'clear':
            clear()
            print(banner.lobby())
        elif option.lower() == 'cscan':
            for ips in ip_target:
                execute.scan_wifi_clients(ips, get_mac_address(ips))
        elif option.lower() == 'mcscan':
            execute.scan_wifi_clients(input("[+] IP Address: "), input("[+] MAC target: ").replace('-', ':'))
        elif option.lower() == 'boost':
            tools.main()
        elif option.lower() == 'sproxy':
            execute.proxy()
        elif option.lower() == 'proxy':
            start_proxy(local_ip, local_port, input("[+] Proxy IP: "), int(input("[+] Proxy port: ")))
            start_tor_proxy()
        elif option.lower() == 'lockall':
            if available:
                for ip in available:
                    if ip in ip_target:
                        pass
                    else:
                        ip_target.append(ip)
                print("Locking all available ip address successfully")
                table_print(["Locked IP Address"], ['{}'.format('\n'.join(ip_target))])
            else:
                print("There's no available ip address currently.")
        elif option.lower() == 'monitor1':
            monitor.start()
        elif option.lower() == 'monitor2':
            monitor.mitm()
        elif option.lower() == 'help' or option.lower() == 'h':
            table_print(['Available Commands'], ['{}'.format('\n'.join(['scan - [scan near wifi]', 'iface - [scanning near iface]', 'gateway - [scanning near gateway]', 'sniff/msniff - [sniff ip address(require alock)]', 'attack - [attack locked IP address]', 'alock - [to lock ipaddress target]', 'remv - [remove 1 locked ip address]', 'rall - [remove all locked ip]', 'locked - [view all locked IP address]', 'available - [view all available IP(require iface)]', 'clear - [clear session]', 'boost - [boost ur wi-fi]', 'sproxy - [start proxy sniffer server]', 'cscan/mcscan - [scanning locked ip network]', 'lockall - [lock all available ip]', 'monitor1 - [monitor network through traffic]', 'mac - [get mac address from IP]', 'proxy - [connect into a proxy]', 'netsniff - [find who is using your wifi and get their mac]']))])
