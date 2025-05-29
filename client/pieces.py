import hashlib

class PieceManager:
    def __init__(self, data: bytes = None, piece_length=1024):
        self.piece_length = piece_length
        self.pieces = self.split_into_pieces(data) if data else []
        self.hashes = [self.compute_hash(piece) for piece in self.pieces]

    def split_into_pieces(self, data: bytes):
        """Split full data into equal-length pieces."""
        if not data:
            return []
        return [data[i:i + self.piece_length] for i in range(0, len(data), self.piece_length)]

    def compute_hash(self, piece: bytes):
        """Return SHA-1 hash of a single piece."""
        return hashlib.sha1(piece).hexdigest()

    def get_piece(self, index: int):
        """Return the piece at given index."""
        if 0 <= index < len(self.pieces):
            return self.pieces[index]
        return None

    def get_hash(self, index: int):
        """Return expected hash for a specific piece."""
        if 0 <= index < len(self.hashes):
            return self.hashes[index]
        return None

    def total_pieces(self):
        """Return total number of pieces."""
        return len(self.pieces)

    def verify_piece(self, index: int, data: bytes):
        """Verify if the received piece matches the expected hash."""
        expected_hash = self.get_hash(index)
        actual_hash = self.compute_hash(data)
        return expected_hash == actual_hash

    def combine_pieces(self):
        """Return the full data by combining all pieces."""
        return b''.join(self.pieces)

    def load_from_file(self, file_path):
        """Load a file and split it into pieces."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            self.pieces = self.split_into_pieces(data)
            self.hashes = [self.compute_hash(piece) for piece in self.pieces]
            print(f"[✓] Loaded '{file_path}' into {len(self.pieces)} pieces.")
        except Exception as e:
            print(f"[✗] Failed to load file: {e}")

    def save_to_file(self, output_path):
        """Combine pieces and save them to a file."""
        try:
            with open(output_path, 'wb') as f:
                f.write(self.combine_pieces())
            print(f"[✓] Saved combined pieces to '{output_path}'")
        except Exception as e:
            print(f"[✗] Failed to write combined file: {e}")
