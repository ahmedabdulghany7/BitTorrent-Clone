import hashlib
import os
import json

CHUNK_SIZE = 1024 * 512  # 512KB

def split_file(filepath):
    chunks = []
    with open(filepath, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            chunks.append(chunk)
    return chunks

def hash_data(data):
    return hashlib.sha1(data).hexdigest()

def generate_metadata(filepath):
    chunks = split_file(filepath)
    chunk_hashes = [hash_data(chunk) for chunk in chunks]
    info_hash = hash_data("".join(chunk_hashes).encode())

    metadata = {
        "filename": os.path.basename(filepath),
        "size": os.path.getsize(filepath),
        "chunks": chunk_hashes,
        "info_hash": info_hash
    }

    with open(filepath + ".meta.json", "w") as f:
        json.dump(metadata, f)

    return metadata
