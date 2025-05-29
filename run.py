import os
import socket
import time
import threading
import requests
from app import app, peer_tracker, SHARED_FOLDER, TORRENT_FOLDER
from torrent.torrent_creator import create_torrent
import sys
from werkzeug.serving import make_server

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        # Create a socket to get the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def get_public_ip():
    """Get the public IP address of the machine using multiple services."""
    services = [
        {
            'url': 'https://api.ipify.org?format=json',
            'parser': lambda r: r.json()['ip']
        },
        {
            'url': 'https://ifconfig.me/ip',
            'parser': lambda r: r.text.strip()
        },
        {
            'url': 'https://icanhazip.com',
            'parser': lambda r: r.text.strip()
        },
        {
            'url': 'https://api.myip.com',
            'parser': lambda r: r.json()['ip']
        },
        {
            'url': 'https://ip.seeip.org/jsonip',
            'parser': lambda r: r.json()['ip']
        },
        {
            'url': 'https://ipinfo.io/ip',
            'parser': lambda r: r.text.strip()
        },
        {
            'url': 'https://wtfismyip.com/text',
            'parser': lambda r: r.text.strip()
        }
    ]
    
    for service in services:
        try:
            print(f"Trying to get IP from {service['url']}...")
            response = requests.get(service['url'], timeout=5)
            if response.status_code == 200:
                ip = service['parser'](response)
                print(f"Successfully got IP: {ip}")
                return ip
        except Exception as e:
            print(f"Failed to get IP from {service['url']}: {str(e)}")
            continue
    
    # If all services fail, try a more direct approach
    try:
        print("Trying direct connection method...")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"Warning: Using local IP {local_ip} as fallback")
        return local_ip
    except Exception as e:
        print(f"Failed to get IP using socket method: {str(e)}")
        return "127.0.0.1"

def ensure_directories():
    """Ensure all required directories exist."""
    directories = ['uploads', 'torrents', 'shared', 'downloads']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def create_torrents_for_existing_files():
    """Create torrent files for all existing shared files."""
    print("\nCreating torrents for existing files...")
    public_ip = get_public_ip()
    for filename in os.listdir(SHARED_FOLDER):
        file_path = os.path.join(SHARED_FOLDER, filename)
        if os.path.isfile(file_path):
            torrent_path = os.path.join(TORRENT_FOLDER, f"{filename}.torrent")
            if not os.path.exists(torrent_path):
                try:
                    # Use public IP for torrent creation
                    create_torrent(file_path, f"http://{public_ip}:5000/announce", torrent_path)
                    print(f"Created torrent for: {filename}")
                except Exception as e:
                    print(f"Error creating torrent for {filename}: {str(e)}")

def print_network_status():
    """Print current network status with real-time updates."""
    def status_task():
        last_peer_count = 0
        last_file_count = 0
        
        while True:
            active_peers = len([p for p in peer_tracker.peers.values() 
                              if time.time() - p['last_seen'] < 300])
            shared_files = len(peer_tracker.file_peers)
            
            # Only update if there's a change
            if active_peers != last_peer_count or shared_files != last_file_count:
                if active_peers > last_peer_count:
                    print(f"\n[+] New peer joined! Total peers: {active_peers}")
                elif active_peers < last_peer_count:
                    print(f"\n[-] Peer disconnected! Remaining peers: {active_peers}")
                
                if shared_files > last_file_count:
                    print(f"[+] New file shared! Total files: {shared_files}")
                elif shared_files < last_file_count:
                    print(f"[-] File removed! Remaining files: {shared_files}")
                
                print(f"\nNetwork Status:")
                print(f"Active Peers: {active_peers}")
                print(f"Shared Files: {shared_files}")
                print("-" * 30)
                
                last_peer_count = active_peers
                last_file_count = shared_files
            
            time.sleep(1)  # Check every second
    
    status_thread = threading.Thread(target=status_task, daemon=True)
    status_thread.start()

def start_peer_cleanup():
    """Start periodic cleanup of inactive peers."""
    def cleanup_task():
        while True:
            peer_tracker.cleanup_old_peers()
            time.sleep(60)  # Clean up every minute
    
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()

def run_server(port):
    """Run the Flask server on a specific port."""
    server = make_server(local_ip, port, app)
    print(f"Starting server on port {port}...")
    server.serve_forever()

if __name__ == '__main__':
    print("\nChecking network connectivity...")
    public_ip = get_public_ip()
    local_ip = get_local_ip()
    
    # Print initial server information
    print("\n=== BitTorrent Clone Server ===")
    print(f"Local IP: {local_ip}")
    print(f"Public IP: {public_ip}")
    print("\nServer will be available on:")
    print(f"Port 5000: http://{local_ip}:5000")
    print(f"Port 5001: http://{local_ip}:5001")
    print(f"Port 5002: http://{local_ip}:5002")
    print(f"Port 5003: http://{local_ip}:5003")
    
    # Check if we're behind a NAT
    if public_ip == local_ip:
        print("\nWARNING: Public IP matches Local IP. You might be:")
        print("1. Behind a NAT/firewall")
        print("2. Using a VPN")
        print("3. Have a direct internet connection")
    
    print("\nIMPORTANT: To make the server accessible from the internet:")
    print("1. Configure port forwarding on your router:")
    print("   - Forward external ports 5000-5003 to internal ports 5000-5003")
    print("   - Forward external port 6881 to internal port 6881")
    print("2. Make sure your firewall allows these ports")
    print("3. Test the connection by visiting the public web interface")
    print("4. If using a VPN, make sure it allows port forwarding")
    print("==============================\n")
    
    # Ensure all required directories exist
    ensure_directories()
    
    # Create torrents for existing files
    create_torrents_for_existing_files()
    
    # Start peer cleanup task
    start_peer_cleanup()
    
    # Start network status monitoring
    print_network_status()
    
    # Start servers on different ports
    ports = [5000, 5001, 5002, 5003]
    server_threads = []
    
    for port in ports:
        thread = threading.Thread(target=run_server, args=(port,), daemon=True)
        server_threads.append(thread)
        thread.start()
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down servers...")
        sys.exit(0)