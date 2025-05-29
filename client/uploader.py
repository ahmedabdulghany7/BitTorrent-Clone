import socket
import threading
import logging
import os
import time
import struct
from client import messages

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

def get_file_pieces(file_path, piece_length):
    pieces = []
    with open(file_path, 'rb') as f:
        while True:
            piece = f.read(piece_length)
            if not piece:
                break
            # Pad the last piece if necessary
            if len(piece) < piece_length:
                piece = piece + b'\x00' * (piece_length - len(piece))
            pieces.append(piece)
    return pieces

def handle_client(conn, addr, pieces, info_hash, peer_id):
    try:
        # Set socket timeout
        conn.settimeout(30)  # 30 second timeout
        
        # Receive and validate handshake
        handshake = conn.recv(68)
        if not handshake or not messages.parse_handshake(handshake, info_hash):
            logging.error(f"Invalid handshake from {addr}, received: {handshake}")
            return

        # Send handshake back
        conn.send(messages.create_handshake(info_hash, peer_id))
        logging.debug(f"Sent handshake to {addr}")

        # Send bitfield
        bitfield = bytearray([0] * ((len(pieces) + 7) // 8))
        for i in range(len(pieces)):
            if pieces[i] is not None:
                bitfield[i // 8] |= (1 << (7 - (i % 8)))
        conn.send(messages.create_bitfield_message(bitfield))
        logging.debug(f"Sent bitfield to {addr}")
        logging.debug(f"Bitfield length: {len(bitfield)}")

        last_activity = time.time()
        while True:
            # Check for timeout
            if time.time() - last_activity > 60:  # 60 second inactivity timeout
                logging.warning(f"Connection to {addr} timed out due to inactivity")
                break

            try:
                msg = conn.recv(4096)
                if not msg:
                    logging.debug(f"No message received from {addr}")
                    break

                logging.debug(f"Received message of length {len(msg)} from {addr}")
                msg_type, index, payload = messages.parse_message(msg)
                logging.debug(f"Parsed message - type: {msg_type}, payload length: {len(payload) if payload else 0}")

                if msg_type == messages.INTERESTED:
                    logging.debug(f"Peer {addr} sent interested")
                    conn.send(messages.create_unchoke_message())
                    logging.debug(f"Sent unchoke to {addr}")
                elif msg_type == messages.REQUEST:
                    index, begin, length = struct.unpack(">III", payload)
                    logging.debug(f"Received request from {addr} - index: {index}, begin: {begin}, length: {length}")
                    if index < len(pieces) and pieces[index] is not None:
                        piece = pieces[index]
                        if begin + length <= len(piece):
                            conn.send(messages.create_piece_message(index, begin, piece[begin:begin + length]))
                            logging.debug(f"Sent piece {index} to {addr}")
                            logging.debug(f"Piece data length: {len(piece[begin:begin + length])}")
                        else:
                            logging.error(f"Invalid piece request: begin={begin}, length={length}, piece_length={len(piece)}")
                    else:
                        logging.error(f"Invalid piece index: {index}")
                elif msg_type == messages.CHOKE:
                    logging.debug(f"Peer {addr} sent choke")
                    break
                elif msg_type == messages.UNCHOKE:
                    logging.debug(f"Peer {addr} sent unchoke")
                elif msg_type == messages.NOT_INTERESTED:
                    logging.debug(f"Peer {addr} sent not interested")
                    break
                else:
                    logging.warning(f"Unknown message type {msg_type} from {addr}")

                last_activity = time.time()

            except socket.timeout:
                logging.warning(f"Socket timeout for {addr}")
                break
            except Exception as e:
                logging.error(f"Error handling message from {addr}: {e}")
                break

    except Exception as e:
        logging.error(f"Error handling peer {addr}: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        logging.info(f"Connection to {addr} closed")

def start_upload_server(pieces, info_hash, peer_id, port=None):
    if port is None:
        port = find_available_port()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind(('0.0.0.0', port))  # Bind to all interfaces
    except Exception as e:
        logging.error(f"Failed to bind to port {port}: {e}")
        raise
    server_socket.listen(5)
    logging.info(f"Upload server started on port {port}")

    try:
        while True:
            conn, addr = server_socket.accept()
            logging.debug(f"Accepted connection from {addr}")
            thread = threading.Thread(
                target=handle_client,
                args=(conn, addr, pieces, info_hash, peer_id)
            )
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
    finally:
        server_socket.close()

def find_available_port(start_port=6881, max_attempts=10):
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                return port
        except OSError:
            continue
    raise OSError(f"Could not find an available port after {max_attempts} attempts")

def find_file(filename):
    try:
        if os.path.exists(filename):
            if os.access(filename, os.R_OK):
                return filename
            else:
                raise PermissionError(f"No read permission for {filename}")
        
        shared_path = os.path.join("shared", filename)
        if os.path.exists(shared_path):
            if os.access(shared_path, os.R_OK):
                return shared_path
            else:
                raise PermissionError(f"No read permission for {shared_path}")
        
        raise FileNotFoundError(f"{filename} not found in current or shared directory.")
    except Exception as e:
        logging.error(f"Error finding file {filename}: {e}")
        raise

if __name__ == "__main__":
    import sys
    from torrent.torrent_parser import TorrentFile
    from client.announce import announce_to_tracker

    if len(sys.argv) != 2:
        print("Usage: python -m client.uploader <torrent_file>")
        sys.exit(1)

    torrent_path = sys.argv[1]
    torrent = TorrentFile(torrent_path)
    peer_id = b'-PY0001-' + os.urandom(12)

    # Convert info_hash to bytes if it's a string
    info_hash = torrent.info_hash
    if isinstance(info_hash, str):
        info_hash = bytes.fromhex(info_hash)
    logging.info(f"Info Hash: {info_hash.hex()}")

    # Get pieces from the original file
    try:
        file_path = find_file(torrent.name)
        pieces = get_file_pieces(file_path, torrent.piece_length)
        logging.info(f"Loaded {len(pieces)} pieces from file")
    except Exception as e:
        logging.error(f"Failed to load file: {e}")
        sys.exit(1)

    # Start server and get the port
    port = find_available_port()
    logging.info(f"Starting upload server on port {port}")
    
    # Announce to tracker with the actual port
    try:
        announce_to_tracker(torrent, port=port)
        logging.info("Successfully announced to tracker")
    except Exception as e:
        logging.error(f"Failed to announce to tracker: {e}")
        sys.exit(1)
    
    # Start the server
    try:
        start_upload_server(pieces, info_hash, peer_id, port=port)
    except KeyboardInterrupt:
        logging.info("Server stopped by user")
    except Exception as e:
        logging.error(f"Server error: {e}")
        sys.exit(1)