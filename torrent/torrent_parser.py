import bencodepy
import hashlib
import os

def find_file(filename):
    if os.path.exists(filename):
        return filename
    shared_path = os.path.join("shared", filename)
    if os.path.exists(shared_path):
        return shared_path
    raise FileNotFoundError(f"{filename} not found in current or shared directory.")

class TorrentFile:
    def __init__(self, file_path):
        self.file_path = file_path
    
        with open(file_path, 'rb') as f:
            self.metainfo = bencodepy.decode(f.read())

        self._parse_info()

    def _parse_info(self):
        self.announce = self.metainfo[b'announce'].decode()
        self.info = self.metainfo[b'info']
        self.name = self.info[b'name'].decode()
        self.length = self.info[b'length']
        self.piece_length = self.info[b'piece length']
        self.pieces_raw = self.info[b'pieces']
        self.piece_hashes = [
            self.pieces_raw[i:i + 20]
            for i in range(0, len(self.pieces_raw), 20)
        ]
        self.info_hash = hashlib.sha1(bencodepy.encode(self.info)).digest()

    def num_pieces(self):
        return len(self.piece_hashes)

    def get_piece_hash(self, index):
        if 0 <= index < len(self.piece_hashes):
            return self.piece_hashes[index]
        return None

    def print_summary(self):
        print(f"Tracker URL: {self.announce}")
        print(f"File Name: {self.name}")
        print(f"File Size: {self.length} bytes")
        print(f"Piece Size: {self.piece_length} bytes")
        print(f"Number of Pieces: {self.num_pieces()}")
        print(f"Info Hash: {self.info_hash.hex()}")
    
    def get_all_pieces(self):
        try:
            with open(find_file(self.name), "rb") as f:
                data = f.read()
                return [data[i:i+self.piece_length] for i in range(0, len(data), self.piece_length)]
        except Exception as e:
            print(f"Error reading file: {e}")
            return []
    
    



if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m torrent.torrent_parser <torrent_file>")
        sys.exit(1)

    torrent = TorrentFile(sys.argv[1])
    torrent.print_summary()
