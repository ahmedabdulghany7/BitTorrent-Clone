import sys
import socket
import threading
import os
from torrent.torrent_parser import TorrentFile
from client.pieces import PieceManager
from client.uploader import start_upload_server
from client.downloader import download_piece
from client.announce import announce_to_tracker

def write_file(pieces, filename="output_file.txt"):
    with open(filename, "wb") as f:
        for piece in pieces:
            f.write(piece)
    print(f"[✓] File written to {filename}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m client.client <torrent_file>")
        exit(1)

    # Parse .torrent file
    torrent = TorrentFile(sys.argv[1])
    port = 6881
    ip = socket.gethostbyname(socket.gethostname())
    print(f"[*] Your IP: {ip}, Port: {port}")

    # Read file content (if you're a seeder)
    try:
        with open(torrent.file_path, "rb") as f:
            data = f.read()
        piece_manager = PieceManager(data)
        total_pieces = piece_manager.total_pieces()
        print(f"[*] File split into {total_pieces} pieces.")
    except Exception as e:
        print(f"[!] Failed to read file: {e}")
        piece_manager = None
        total_pieces = torrent.total_pieces
        print(f"[*] Expecting {total_pieces} pieces from peers.")

    # Start upload server if you have the file
    if piece_manager:
        peer_id = os.urandom(20).hex()  # Generate random peer ID
        threading.Thread(target=start_upload_server, args=(piece_manager.pieces, torrent.info_hash, peer_id, port), daemon=True).start()

    # Get peers from tracker
    peers = announce_to_tracker(torrent, port)

    # Start downloading
    downloaded_pieces = [None] * total_pieces
    if piece_manager:
        downloaded_pieces[0] = piece_manager.get_piece(0)  # Simulate having first piece

    for i in range(total_pieces):
        if downloaded_pieces[i] is not None:
            continue

        for peer in peers:
            if peer["ip"] == ip and peer["port"] == port:
                continue  # Skip self
            print(f"[>] Trying to download piece {i} from {peer['ip']}:{peer['port']}")
            piece = download_piece(peer["ip"], peer["port"], i)
            if piece:
                if piece_manager:
                    if piece_manager.verify_piece(i, piece):
                        downloaded_pieces[i] = piece
                        print(f"[✓] Piece {i} downloaded and verified.")
                        break
                    else:
                        print(f"[✗] Piece {i} hash mismatch.")
                else:
                    downloaded_pieces[i] = piece
                    print(f"[✓] Piece {i} downloaded (no verification).")
                    break

    # Final result
    if None in downloaded_pieces:
        print("[!] Some pieces are missing. File incomplete.")
    else:
        write_file(downloaded_pieces)
