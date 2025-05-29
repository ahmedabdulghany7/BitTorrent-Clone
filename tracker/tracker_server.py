import os 
import time 
import threading 
from flask import Flask, request, jsonify 
from http.server import SimpleHTTPRequestHandler 
from socketserver import TCPServer 
from tracker.utils import PeerManager

app = Flask(__name__) 
peer_manager = PeerManager()

@app.route("/announce", methods=["POST"]) 
def announce(): 
    data = request.get_json() 
    info_hash = data.get("info_hash") 
    peer_port = data.get("port") 
    peer_ip = data.get("ip") or request.remote_addr  # Use IP from client if provided

    if not info_hash or not peer_port:
        return jsonify({"error": "Missing info_hash or port"}), 400

    try:
        peer_port = int(peer_port)
    except ValueError:
        return jsonify({"error": "Invalid port"}), 400

    # Ensure info_hash is in the correct format
    if isinstance(info_hash, str):
        try:
            # Convert hex string to bytes for internal storage
            info_hash = bytes.fromhex(info_hash)
        except ValueError:
            return jsonify({"error": "Invalid info_hash format"}), 400

    peer_manager.add_peer(info_hash, peer_ip, peer_port)

    peers = peer_manager.get_peers(info_hash, exclude_ip=peer_ip, exclude_port=peer_port)

    return jsonify({
        "interval": 1800,
        "peers": peers
    })


def run_tracker(): 
    print("[*] Tracker server running on http://0.0.0.0:8000") 
    app.run(host="0.0.0.0", port=8000, threaded=True)

def run_http_file_server(directory="shared", port=8080): 
    os.makedirs(directory, exist_ok=True) 
    os.chdir(directory) 
    handler = SimpleHTTPRequestHandler 
    httpd = TCPServer(("", port), handler) 
    print(f"[*] HTTP file server running on http://0.0.0.0:{port} (serving '{directory}/')") 
    httpd.serve_forever()

if __name__ == "__main__":
    threading.Thread(target=run_tracker, daemon=True).start() 
    threading.Thread(target=run_http_file_server, args=("shared", 8080), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down servers...")
