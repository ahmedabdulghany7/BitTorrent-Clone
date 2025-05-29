import os
import hashlib
import bencodepy

PIECE_SIZE = 256 * 1024  # 256 KB
DEFAULT_TRACKER_URL = "http://localhost:5001/announce"  # Updated port

def get_file_pieces(file_path):
    with open(file_path, 'rb') as f:
        while True:
            piece = f.read(PIECE_SIZE)
            if not piece:
                break
            yield piece

def create_torrent(file_path, tracker_url=DEFAULT_TRACKER_URL, output_path=None):
    file_name = os.path.basename(file_path)
    file_path = os.path.abspath(file_path)
    file_size = os.path.getsize(file_path)

    if output_path is None:
        output_path = os.path.join("torrents", f"{file_name}.torrent")

    print(f"[+] Creating torrent for: {file_name} ({file_size} bytes)")

    pieces = b''.join(
        hashlib.sha1(piece).digest()
        for piece in get_file_pieces(file_path)
    )

    torrent_data = {
        b'announce': tracker_url.encode(),
        b'info': {
            b'name': file_name.encode(),
            b'length': file_size,
            b'piece length': PIECE_SIZE,
            b'pieces': pieces
        }
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(bencodepy.encode(torrent_data))

    print(f"[✓] Torrent file saved as: {output_path}")
    return output_path


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python -m torrent.torrent_creator <input_file> <tracker_url> <output_torrent_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    tracker_url = sys.argv[2]
    output_file = sys.argv[3]

    create_torrent(input_file, tracker_url, output_file)
