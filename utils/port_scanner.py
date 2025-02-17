import sys
import time
import socket
import csv
from global_data import multi_scan_result, bulk_port_scan_result
from utils.checker import check_host
from flask_socketio import SocketIO

def scan_ports(host, start_port, end_port, socketio, only_ports=False):
    print(f"[DEBUG] scan_ports() called with host: {host}, start_port: {start_port}, end_port: {end_port}")
    
    open_ports = []
    total_ports = end_port - start_port + 1
    estimated_total_time = total_ports * 0.5  # assuming 0.5 sec per port scan
    socketio.emit(
        'update', 
        {'message': f"Estimated total time: {estimated_total_time:.2f} sec", 'progress': 0}
    )
    
    for index, port in enumerate(range(start_port, end_port + 1), start=1):
        message = (f"Checking port {port} ({index}/{total_ports}) on host {host} | "
                   f"ETA: {max((total_ports - index) * 0.5, 0):.2f} sec")
        sys.stdout.write("\r" + message)
        sys.stdout.flush()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)

        socketio.emit(
            'update', 
            {'message': message, 'progress': (index / total_ports) * 100}
        )
        socketio.sleep(0.5)
    print()  # move to new line after progress
    
    if not only_ports:
        # Check certificates for each open port
        certificates = {}
        for port in open_ports:
            try:
                cert_result = check_host(host, port)
                certificates[port] = cert_result
            except Exception as e:
                certificates[port] = {"error": str(e)}
    else:
        certificates = {}
    
    result_data = {
        "hostname": host,
        "checked_ports_range": f"{start_port}-{end_port}",
        "open_ports": open_ports,
        "reachable": "Yes",
        "certificates": certificates,
        "scan_type": "port" if only_ports else "certificate"
    }
    
    multi_scan_result.clear()
    multi_scan_result.update(result_data)
    socketio.emit(
        'completion', 
        {
            'message': "Scanning complete!",
            'hostname': host,
            'startPort': start_port,
            'endPort': end_port,
            'open_ports': open_ports
        }
    )
    return result_data

def scan_bulk_ports(file_path, socketio: SocketIO):
    """
    Reads a CSV file containing (hostname, start_port, end_port).
    Splits multiple hostnames if they're comma-separated.
    Scans each host's ports, emitting real-time progress events (including overall progress).
    Results are stored in the global variable bulk_port_scan_result.
    """
    results = []
    bulk_port_scan_result.clear()  # reset global results
    try:
        with open(file_path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            rows = list(csv_reader)
        
        # 1) Count how many total *hostnames* we'll scan (splitting per row if needed)
        total_hosts = 0
        for row in rows:
            hostname_field = row.get('hostname', '')
            splitted_hosts = [h.strip() for h in hostname_field.split(',') if h.strip()]
            total_hosts += len(splitted_hosts)

        if total_hosts == 0:
            socketio.emit(
                'update', 
                {'message': "No valid hostnames found in CSV.", 'progress': 100}, 
                namespace='/bulk'
            )
            return results

        socketio.emit(
            'update', 
            {'message': f"Starting bulk port scan for {total_hosts} host(s)...", 'progress': 0}, 
            namespace='/bulk'
        )

        completed_hosts = 0  # how many hosts scanned so far
        # 2) Scan each row, splitting multiple hostnames
        for idx, row in enumerate(rows, start=1):
            hostname_field = row.get('hostname', '')
            start_port_str = row.get('start_port', '0')
            end_port_str   = row.get('end_port', '0')

            try:
                start_port = int(start_port_str)
                end_port   = int(end_port_str)
            except ValueError:
                # skip rows with invalid start/end port
                continue

            # split the hostname cell by comma
            splitted_hosts = [h.strip() for h in hostname_field.split(',') if h.strip()]

            for hostname in splitted_hosts:
                open_ports = []
                total_ports = end_port - start_port + 1

                # Scan each port for this single host
                for i, port in enumerate(range(start_port, end_port + 1), start=1):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        res = s.connect_ex((hostname, port))
                        if res == 0:
                            open_ports.append(port)

                    # Calculate progress for this single host and across all hosts
                    # If total_hosts = sum of splitted hosts, we treat scanning each host
                    # as we did before, but let's do it on a per-host basis:
                    progress_for_host = (i / total_ports) * 100
                    # i.e., 0..100% for the single host

                    # overall progress is # of completed hosts plus fraction for current host
                    overall_progress = (
                        (completed_hosts + (i / total_ports)) / total_hosts
                    ) * 100

                    socketio.emit(
                        'update',
                        {
                            'message': (f"Scanning {hostname} "
                                        f"port {port} ({i}/{total_ports})"),
                            'progress': overall_progress
                        },
                        namespace='/bulk'
                    )
                    socketio.sleep(0.1)

                # Done scanning ports for this host
                results.append({
                    "hostname": hostname,
                    "start_port": start_port,
                    "end_port": end_port,
                    "open_ports": open_ports
                })
                bulk_port_scan_result.append({
                    "hostname": hostname,
                    "start_port": start_port,
                    "end_port": end_port,
                    "open_ports": open_ports
                })

                completed_hosts += 1  # fully done scanning this 1 host

        # 3) Once done, emit final completion
        socketio.emit(
            'completion',
            {
                'message': "Bulk port scanning complete!",
                'results': results
            },
            namespace='/bulk'
        )

    except Exception as e:
        socketio.emit(
            'update',
            {'message': f"Error during bulk scan: {str(e)}", 'progress': 100},
            namespace='/bulk'
        )

    return results
