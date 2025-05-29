import os
import sys
import requests
import hashlib
import logging
import socket
import threading
import time
from torrent.torrent_parser import TorrentFile
from client.connection import PeerConnection
from client import messages

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

OUTPUT_DIR = "downloads"
TRACKER_URL = "http://localhost:5001/announce"  # Updated to match Flask app port
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def announce_to_tracker(info_hash, port):
    try:
        # Convert info_hash to hex string for HTTP request if it's bytes
        if isinstance(info_hash, bytes):
            info_hash = info_hash.hex()
        
        payload = {
            "info_hash": info_hash,
            "port": port,
            "ip": get_local_ip(),
            "uploaded": 0,
            "downloaded": 0,
            "left": 0,  # We're downloading, so left is 0
            "event": "started"
        }
        
        res = requests.post(TRACKER_URL, json=payload)
        res.raise_for_status()
        peers = res.json().get("peers", [])
        logging.info(f"Received {len(peers)} peers from tracker")
        return peers
    except Exception as e:
        logging.error(f"Tracker error: {e}")
        return []

def save_file(file_path, pieces):
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "wb") as f:
            for piece in pieces:
                if piece is not None:
                    f.write(piece)
        logging.info(f"File saved: {file_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save file: {e}")
        return False

def verify_piece(piece_data, expected_hash):
    if isinstance(expected_hash, str):
        expected_hash = bytes.fromhex(expected_hash)
    computed_hash = hashlib.sha1(piece_data).digest()
    return computed_hash == expected_hash

def download_piece(ip, port, index, info_hash, peer_id, piece_hash, piece_length, retry_count=0):
    if retry_count >= MAX_RETRIES:
        logging.error(f"Max retries reached for piece {index} from {ip}:{port}")
        return None

    conn = None
    try:
        conn = PeerConnection(ip, port)
        if not conn.connect():
            logging.error(f"Failed to connect to {ip}:{port}")
            return None

        # Set socket timeout
        conn.sock.settimeout(30)  # 30 second timeout

        # Ensure info_hash and peer_id are bytes
        if isinstance(info_hash, str):
            info_hash = bytes.fromhex(info_hash)
        if isinstance(peer_id, str):
            peer_id = peer_id.encode('utf-8')

        # Send handshake
        handshake = messages.create_handshake(info_hash, peer_id)
        conn.send(handshake)
        response = conn.receive_exact(68)  # Handshake is 68 bytes
        if not response or not messages.parse_handshake(response, info_hash):
            logging.error(f"Invalid handshake from {ip}:{port}, response: {response}")
            return None
        logging.debug(f"Handshake successful with {ip}:{port}")

        # Send interested
        conn.send(messages.create_interested_message())
        logging.debug(f"Sent interested to {ip}:{port}")

        # Wait for unchoke
        while True:
            response = conn.receive()
            if not response:
                logging.error(f"No response from {ip}:{port} after interested")
                return None
            msg_type, _, payload = messages.parse_message(response)
            if msg_type == messages.UNCHOKE:
                logging.debug(f"Received unchoke from {ip}:{port}")
                break
            elif msg_type == messages.BITFIELD:
                logging.debug(f"Received bitfield from {ip}:{port}")
                continue  # Ignore bitfield for now
            else:
                logging.error(f"Peer {ip}:{port} sent unexpected msg_type {msg_type}")
                continue

        # Request piece
        request_msg = messages.create_request_message(index, 0, piece_length)
        conn.send(request_msg)
        logging.debug(f"Sent request for piece {index} to {ip}:{port}")
        logging.debug(f"Request details - index: {index}, begin: 0, length: {piece_length}")
        logging.debug(f"Request message length: {len(request_msg)}")

        response = conn.receive()
        if not response:
            logging.error(f"No response for piece {index} from {ip}:{port}")
            return None

        logging.debug(f"Received response of length {len(response)} from {ip}:{port}")
        msg_type, piece_index, payload = messages.parse_message(response)
        logging.debug(f"Parsed message - type: {msg_type}, piece_index: {piece_index}, payload length: {len(payload) if payload else 0}")

        if msg_type == messages.PIECE and piece_index == index and payload:
            # Verify piece hash
            if verify_piece(payload, piece_hash):
                logging.debug(f"Piece {index} hash verified from {ip}:{port}")
                return payload
            else:
                logging.error(f"Hash mismatch for piece {index} from {ip}:{port}")
                logging.debug(f"Expected hash: {piece_hash.hex()}")
                logging.debug(f"Received hash: {hashlib.sha1(payload).digest().hex()}")
                time.sleep(RETRY_DELAY)
                return download_piece(ip, port, index, info_hash, peer_id, piece_hash, piece_length, retry_count + 1)
        else:
            logging.error(f"Invalid or empty piece received from {ip}:{port}")
            logging.debug(f"Message type: {msg_type}, Expected: {messages.PIECE}")
            logging.debug(f"Piece index: {piece_index}, Expected: {index}")
            return None

    except socket.timeout:
        logging.warning(f"Socket timeout for piece {index} from {ip}:{port}")
        time.sleep(RETRY_DELAY)
        return download_piece(ip, port, index, info_hash, peer_id, piece_hash, piece_length, retry_count + 1)
    except Exception as e:
        logging.error(f"Failed to download piece {index} from {ip}:{port}: {e}")
        time.sleep(RETRY_DELAY)
        return download_piece(ip, port, index, info_hash, peer_id, piece_hash, piece_length, retry_count + 1)
    finally:
        if conn:
            conn.close()

def download_file(torrent_path, listen_port=6881):
    torrent = TorrentFile(torrent_path)
    torrent.print_summary()

    # Convert info_hash to bytes if it's a string
    info_hash = torrent.info_hash
    if isinstance(info_hash, str):
        info_hash = bytes.fromhex(info_hash)
    logging.info(f"Info Hash: {info_hash.hex()}")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, torrent.name)

    logging.info("Announcing to tracker...")
    peers = announce_to_tracker(torrent.info_hash, listen_port)
    if not peers:
        logging.error("No peers returned by tracker.")
        return False

    logging.info(f"{len(peers)} peer(s) received from tracker.")

    num_pieces = torrent.num_pieces()
    pieces = [None] * num_pieces
    downloaded = [False] * num_pieces
    peer_id = b'-PY0001-' + os.urandom(12)

    for index in range(num_pieces):
        piece_length = min(torrent.piece_length, torrent.length - index * torrent.piece_length)
        piece_hash = torrent.get_piece_hash(index)
        
        if piece_hash is None:
            logging.error(f"No hash found for piece {index}")
            continue

        for peer in peers:
            ip, port = peer["ip"], peer["port"]
            piece_data = download_piece(
                ip, port, index, info_hash, peer_id,
                piece_hash, piece_length
            )

            if piece_data:
                pieces[index] = piece_data
                downloaded[index] = True
                logging.info(f"Downloaded piece {index} from {ip}:{port}")
                break

        if not downloaded[index]:
            logging.error(f"Failed to download piece {index} from all peers.")
            return False

    if save_file(output_path, pieces):
        logging.info("Download completed successfully!")
        return True
    else:
        logging.error("Failed to save downloaded file.")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m client.downloader <torrent_file>")
        sys.exit(1)

    success = download_file(sys.argv[1])
    sys.exit(0 if success else 1)