import sys
import os
from torrent.torrent_parser import TorrentFile
from client.uploader import start_upload_server

UPLOAD_PORT = 6881
PIECES_DIR = "downloads"

def load_pieces(torrent_path):
    torrent = TorrentFile(torrent_path)
    file_path = os.path.join(PIECES_DIR, torrent.name)

    with open(file_path, "rb") as f:
        data = f.read()

    piece_length = torrent.piece_length
    return [data[i:i+piece_length] for i in range(0, len(data), piece_length)]

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m client.server <torrent_file>")
        sys.exit(1)

    torrent_file = sys.argv[1]
    pieces = load_pieces(torrent_file)

    print("[*] Serving file pieces to peers...")
    start_upload_server(pieces, UPLOAD_PORT)

if __name__ == "__main__":
    main()
