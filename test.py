import ssl
import socket

def get_supported_tls_versions(hostname, port=443, timeout=3):
    """
    Attempts to connect to the host forcing each TLS version (1.0, 1.1, 1.2, 1.3).
    Returns a list of TLS version strings that the host supports.
    """
    supported = []
    try:
        from ssl import TLSVersion, SSLContext, PROTOCOL_TLS_CLIENT
        # Define the TLS versions we want to test
        tls_versions = [
            TLSVersion.TLSv1,    # TLS 1.0
            TLSVersion.TLSv1_1,  # TLS 1.1
            TLSVersion.TLSv1_2,  # TLS 1.2
            TLSVersion.TLSv1_3   # TLS 1.3
        ]
        version_names = {
            TLSVersion.TLSv1: "TLSv1.0",
            TLSVersion.TLSv1_1: "TLSv1.1",
            TLSVersion.TLSv1_2: "TLSv1.2",
            TLSVersion.TLSv1_3: "TLSv1.3",
        }
        for ver in tls_versions:
            try:
                context = SSLContext(PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ver
                context.maximum_version = ver
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # If handshake succeeds, we record that version as supported.
                        supported.append(version_names[ver])
            except Exception:
                # If an exception occurs, that version is likely not supported (or blocked locally)
                print(version_names[ver])
                pass
    except ImportError:
        # Fallback for older Python versions (not recommended for TLSv1.1+)
        protocols = [
            (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
            (getattr(ssl, "PROTOCOL_TLSv1_1", None), "TLSv1.1"),
            (ssl.PROTOCOL_TLSv1_2, "TLSv1.2")
        ]
        for proto, name in protocols:
            if proto is None:
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


if __name__ == "__main__":
    print(get_supported_tls_versions("wts.aig.net"))