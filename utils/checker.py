import ssl
import socket
import warnings
import csv
import os
import time  
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
import concurrent.futures
from global_data import bulk_port_scan_result


def check_network_connection(hostname, port, timeout=3):
    try:
        socket.create_connection((hostname, port), timeout=timeout)
        return True
    except (socket.timeout, socket.error):
        return False

def is_self_signed(cert):
    if not cert:
        return False
    # A simple comparison: if issuer == subject, assume self-signed.
    return cert.get("issuer") == cert.get("subject")


# def get_tls_and_certificate_details(hostname, port=443):
#     """
#     Legacy method using getpeercert() to extract TLS version and certificate details.
#     (Retained here for completeness; not usually needed now.)
#     """
#     try:
#         warnings.filterwarnings("ignore", category=DeprecationWarning)
#         versions = {
#             'TLSv1.2': ssl.TLSVersion.TLSv1_2,
#             'TLSv1.3': ssl.TLSVersion.TLSv1_3
#         }
#         supported_versions = []
#         for version_name, version in versions.items():
#             try:
#                 context = ssl.create_default_context()
#                 context.minimum_version = version
#                 context.maximum_version = version
#                 with socket.create_connection((hostname, port), timeout=3) as conn:
#                     with context.wrap_socket(conn, server_hostname=hostname) as sock:
#                         cert = sock.getpeercert()
#                         if cert and not is_self_signed(cert):
#                             supported_versions.append(version_name)
#             except (ssl.SSLError, socket.timeout):
#                 continue

#         def extract_cert_details(cert):
#             issuer_details = "\n".join(
#                 f"- {name}: {value}" for item in cert.get('issuer', []) for name, value in item
#             )
#             common_name = next(
#                 (value for field in cert.get("subject", []) for key, value in field if key == "commonName"),
#                 "Unknown"
#             )
#             return {
#                 'valid_from': cert.get('notBefore', 'Unknown'),
#                 'valid_to': cert.get('notAfter', 'Unknown'),
#                 'issuer': issuer_details,
#                 'subject': cert.get('subject', []),
#                 'common_name': common_name
#             }

#         context = ssl.create_default_context()
#         with socket.create_connection((hostname, port), timeout=3) as sock:
#             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 cert = ssock.getpeercert()
#                 cert_details = extract_cert_details(cert)

#         if not is_self_signed(cert):
#             return supported_versions, cert_details

#         # Handle self-signed
#         context.check_hostname = False
#         context.verify_mode = ssl.CERT_NONE
#         with socket.create_connection((hostname, port), timeout=3) as sock:
#             with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 cert = ssock.getpeercert()
#                 cert_details = extract_cert_details(cert)
#         return supported_versions, cert_details
#     except Exception:
#         return None, None
def get_tls_and_certificate_details(hostname, port=443):
    try:
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        
        # Try to import TLSVersion (available in Python 3.7+)
        # Fallback: if older Python, you can handle it below with ssl.PROTOCOL_TLSv1, etc.
        try:
            from ssl import TLSVersion
            versions = {
                'TLSv1.0': TLSVersion.TLSv1,
                'TLSv1.1': TLSVersion.TLSv1_1,
                'TLSv1.2': TLSVersion.TLSv1_2,
                'TLSv1.3': TLSVersion.TLSv1_3
            }
        except ImportError:
            # Fallback for older Python that doesn't have TLSVersion
            # You can use ssl.PROTOCOL_TLSv1, etc. or skip older TLS versions.
            versions = {}

        supported_versions = []

        # Attempt each version
        for version_name, version in versions.items():
            try:
                context = ssl.create_default_context()
                # Force both minimum and maximum version to the same TLS version
                context.minimum_version = version
                context.maximum_version = version

                with socket.create_connection((hostname, port), timeout=3) as conn:
                    with context.wrap_socket(conn, server_hostname=hostname) as sock:
                        cert = sock.getpeercert()
                        if cert and not is_self_signed(cert):
                            supported_versions.append(version_name)
            except (ssl.SSLError, socket.timeout):
                continue

        def extract_cert_details(cert):
            issuer_details = "\n".join(
                f"- {name}: {value}" 
                for item in cert.get('issuer', []) 
                for name, value in item
            )
            common_name = next(
                (value for field in cert.get("subject", []) for key, value in field if key == "commonName"),
                "Unknown"
            )
            return {
                'valid_from': cert.get('notBefore', 'Unknown'),
                'valid_to': cert.get('notAfter', 'Unknown'),
                'issuer': issuer_details,
                'subject': cert.get('subject', []),
                'common_name': common_name
            }

        # Now, extract the certificate details using default context
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_details = extract_cert_details(cert)

        if not is_self_signed(cert):
            return supported_versions, cert_details

        # If it's self-signed, try again ignoring hostname checks
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_details = extract_cert_details(cert)

        return supported_versions, cert_details

    except Exception:
        return None, None


def determine_cert_status(cert_valid_to):
    """
    Given a cert expiry string (e.g. "Apr 14 08:36:03 2025 GMT"), 
    determine status + days left.
    """
    if not cert_valid_to:
        return "Invalid", None
    try:
        expiry_date = datetime.strptime(cert_valid_to, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_date - datetime.now()).days
        if days_left < 0:
            return "Expired", days_left
        elif days_left <= 30:
            return f"Expiring Soon ({days_left} days)", days_left
        return f"Valid ({days_left} days)", days_left
    except Exception as e:
        print(f"Error determining certificate status: {e}")
        return "Invalid", None


def get_der_certificate(hostname, port=443, timeout=3):
    """
    Attempts to get the DER-encoded certificate from the host (binary_form=True).
    """
    try:
        context = ssl._create_unverified_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    return der_cert
    except Exception:
        pass
    # fallback to get_server_certificate -> convert PEM -> DER
    try:
        pem_cert = ssl.get_server_certificate((hostname, port))
        der_cert = ssl.PEM_cert_to_DER_cert(pem_cert)
        return der_cert
    except Exception:
        return None

def parse_der_cert(der_cert):
    """
    Parses DER-encoded cert -> dictionary
    """
    cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
    subject = {}
    for attribute in cert_obj.subject:
        try:
            key = attribute.oid._name
        except AttributeError:
            key = attribute.oid.dotted_string
        subject[key] = attribute.value

    issuer = {}
    for attribute in cert_obj.issuer:
        try:
            key = attribute.oid._name
        except AttributeError:
            key = attribute.oid.dotted_string
        issuer[key] = attribute.value

    try:
        common_name = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        common_name = None

    expiry_date = cert_obj.not_valid_after_utc
    expiry_str = expiry_date.strftime("%b %d %H:%M:%S %Y GMT")
    valid_from = cert_obj.not_valid_before_utc
    valid_from_str = valid_from.strftime("%b %d %H:%M:%S %Y GMT")
    return {
        "subject": subject,
        "issuer": issuer,
        "common_name": common_name,
        "valid_from": valid_from_str,
        "valid_to": expiry_str,
        "expiry_date": expiry_date
    }

# def get_supported_tls_versions(hostname, port=443, timeout=3):
#     supported = []
#     try:
#         from ssl import TLSVersion
#         tls_versions = [TLSVersion.TLSv1_2, TLSVersion.TLSv1_3]
#         version_names = {
#             TLSVersion.TLSv1_2: "TLSv1.2",
#             TLSVersion.TLSv1_3: "TLSv1.3",
#         }
#         for ver in tls_versions:
#             try:
#                 context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#                 context.check_hostname = False
#                 context.verify_mode = ssl.CERT_NONE
#                 context.minimum_version = ver
#                 context.maximum_version = ver
#                 with socket.create_connection((hostname, port), timeout=timeout) as sock:
#                     with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                         supported.append(version_names[ver])
#             except Exception:
#                 pass
#     except ImportError:
#         protocols = [(ssl.PROTOCOL_TLSv1_2, "TLSv1.2")]
#         for proto, name in protocols:
#             try:
#                 context = ssl.SSLContext(proto)
#                 context.check_hostname = False
#                 context.verify_mode = ssl.CERT_NONE
#                 with socket.create_connection((hostname, port), timeout=timeout) as sock:
#                     with context.wrap_socket(sock, server_hostname=hostname) as ssock:
#                         supported.append(name)
#             except Exception:
#                 pass
#     return supported
def get_supported_tls_versions(hostname, port=443, timeout=3):
    supported = []
    try:
        from ssl import TLSVersion
        tls_versions = [TLSVersion.TLSv1, TLSVersion.TLSv1_1, TLSVersion.TLSv1_2, TLSVersion.TLSv1_3]
        version_names = {
            TLSVersion.TLSv1:   "TLSv1.0",
            TLSVersion.TLSv1_1: "TLSv1.1",
            TLSVersion.TLSv1_2: "TLSv1.2",
            TLSVersion.TLSv1_3: "TLSv1.3",
        }
        for ver in tls_versions:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                context.minimum_version = ver
                context.maximum_version = ver

                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        
                        supported.append(version_names[ver])
            except Exception:
                pass

    except ImportError:
        protocols = [
            (ssl.PROTOCOL_TLSv1,  "TLSv1.0"), 
            (getattr(ssl, "PROTOCOL_TLSv1_1", None), "TLSv1.1"), 
            (ssl.PROTOCOL_TLSv1_2, "TLSv1.2"),
        ]
        for proto, name in protocols:
            if not proto:
                continue  
            try:
                context = ssl.SSLContext(proto)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported.append(name)
            except Exception:
                pass

    return supported


def check_host(hostname, port=443):
    """
    Main function to check a host's certificate + expiry + TLS versions.
    """
    start_time = time.perf_counter()
    result = {
        'hostname': hostname,
        'port': port,
        'reachable': False,
        'tls_version': [],
        'certificate': {},
        'status': "No Certificate",
        'days_left': None,
        'common_name': None,
        'certificate_type': None,
        'time_taken': None
    }
    try:
        reachable = check_network_connection(hostname, port, timeout=3)
        result['reachable'] = reachable
        if not reachable:
            result['status'] = "Host Unreachable"
            return result

        result['tls_version'] = get_supported_tls_versions(hostname, port, timeout=3)
        der_cert = get_der_certificate(hostname, port, timeout=3)
        if der_cert:
            parsed_cert = parse_der_cert(der_cert)
        else:
            parsed_cert = {}

        if parsed_cert:
            subject = parsed_cert.get("subject", {})
            issuer = parsed_cert.get("issuer", {})
            result['common_name'] = parsed_cert.get("common_name")
            if subject and issuer and subject == issuer:
                result['certificate_type'] = "Self Signed"
            else:
                result['certificate_type'] = "Not Self Signed"
            result['certificate'] = parsed_cert

            expiry_date = parsed_cert.get("expiry_date")
            if expiry_date:
                now = datetime.now(timezone.utc)
                days_left = (expiry_date - now).days
                result['days_left'] = days_left
                result['status'] = "Valid" if days_left >= 0 else "Expired"
            else:
                result['status'] = "No Expiry Info"
        else:
            result['status'] = "No Certificate"
    except Exception as e:
        result['status'] = "Error: " + str(e)
        result['days_left'] = None

    end_time = time.perf_counter()
    elapsed = end_time - start_time
    result['time_taken'] = elapsed
    print(f"Host {hostname}:{port} checked in {elapsed:.2f} seconds", flush=True)
    return result


def check_open_ports(host, start_port, end_port):
    """
    Scans [start_port, end_port] and returns list of open ports.
    """
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((host, port)) == 0:
                    open_ports.append(port)
        except Exception:
            continue
    return open_ports

def process_bulk_ports(file_path):
    """
    Synchronous function that scans open ports for each row in CSV.
    Splits multiple hostnames if needed.
    """
    print("BEBUG: process_bulk_ports is called", flush=True)
    results = []
    try:
        with open(file_path, mode='r', newline='') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for idx, row in enumerate(csv_reader, start=1):
                hostname_field = row.get('hostname')
                if not hostname_field:
                    continue
                try:
                    start_port = int(row.get('start_port'))
                    end_port = int(row.get('end_port'))
                except ValueError:
                    continue

                hostnames = [h.strip() for h in hostname_field.split(',') if h.strip()]

                for hostname in hostnames:
                    open_ports_found = check_open_ports(hostname, start_port, end_port)
                    print(f"BEBUG : {hostname} : {open_ports_found}", flush=True)
                    results.append({
                        "hostname": hostname,
                        "start_port": start_port,
                        "end_port": end_port,
                        "open_ports": open_ports_found
                    })
    except Exception as e:
        print(f"Error processing bulk ports: {e}", flush=True)
    return results


def process_bulk_hosts(file_path):
    """
    Synchronously processes a CSV of hosts for certificate checks in parallel.
    """
    overall_start = time.perf_counter()
    results = []
    try:
        with open(file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            tasks = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                for idx, row in enumerate(csv_reader, start=1):
                    if not row:
                        continue
                    hostname_field = row.get('hostname')
                    if not hostname_field:
                        continue
                    # multiple hostnames
                    hostnames = [h.strip() for h in hostname_field.split(",") if h.strip()]
                    try:
                        port = int(row.get('port', 443))
                    except ValueError:
                        port = 443

                    for hostname in hostnames:
                        print(f"Processing row {idx}: hostname {hostname}, port {port}", flush=True)
                        tasks.append(executor.submit(check_host, hostname, port))

                for future in concurrent.futures.as_completed(tasks):
                    result = future.result()
                    if result:
                        cert = result.get('certificate')
                        if cert and cert != "N/A":
                            if is_self_signed(cert):
                                result['certificate_type'] = "Self Signed"
                            else:
                                result['certificate_type'] = "Not Self Signed"
                        else:
                            result['certificate_type'] = "N/A"
                        results.append(result)
        overall_end = time.perf_counter()
        total_time = overall_end - overall_start
        print(f"Processed bulk hosts in {total_time:.2f} seconds", flush=True)
    except FileNotFoundError:
        print(f"Error: File not found at path {file_path}", flush=True)
    except Exception as e:
        print(f"Error processing bulk hosts: {e}", flush=True)
    return results

def check_bulk_hosts(file_path):
    return process_bulk_hosts(file_path)


def scan_bulk_ports(file_path, socketio):
    """
    Reads a CSV of (hostname, start_port, end_port).
    Splits multiple hosts in one cell. 
    Emits real-time progress events (similar to bulk cert check).
    Stores final results in 'bulk_port_scan_result'.
    """
    try:
        # Clear old results
        bulk_port_scan_result.clear()

        # Read entire CSV first to count total *hostnames*
        with open(file_path, mode='r', newline='') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            rows = list(csv_reader)

        total_hosts = 0
        for row in rows:
            hostname_field = row.get('hostname', '')
            splitted = [h.strip() for h in hostname_field.split(',') if h.strip()]
            total_hosts += len(splitted)

        if total_hosts == 0:
            socketio.emit('update', {
                'message': "No valid hostnames found in CSV.",
                'progress': 100
            }, namespace='/bulk')
            return

        completed = 0

        # Start scanning each row
        for row_idx, row in enumerate(rows, start=1):
            hostname_field = row.get('hostname', '')
            start_port_str = row.get('start_port', '0')
            end_port_str   = row.get('end_port', '0')

            try:
                start_port = int(start_port_str)
                end_port   = int(end_port_str)
            except ValueError:
                continue

            # Split multiple hostnames
            splitted_hosts = [h.strip() for h in hostname_field.split(',') if h.strip()]
            for hostname in splitted_hosts:
                open_ports = check_open_ports(hostname, start_port, end_port)

                # Add to global results
                result_entry = {
                    "hostname": hostname,
                    "start_port": start_port,
                    "end_port": end_port,
                    "open_ports": open_ports
                }
                bulk_port_scan_result.append(result_entry)

                # Update progress
                completed += 1
                progress = int((completed / total_hosts) * 100)
                socketio.emit('update', {
                    'message': f"Scanning {hostname} ({completed}/{total_hosts})",
                    'progress': progress
                }, namespace='/bulk')

                time.sleep(0.1)  # small delay for demo; remove or adjust in production

        # Once done
        socketio.emit('completion', {
            'message': "Bulk port scanning complete!"
        }, namespace='/bulk')

    except Exception as e:
        socketio.emit('update', {
            'message': f"Error during bulk scan: {e}",
            'progress': 100
        }, namespace='/bulk')
