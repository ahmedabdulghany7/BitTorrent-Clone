import struct
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

# Message types
CHOKE = 0
UNCHOKE = 1
INTERESTED = 2
NOT_INTERESTED = 3
HAVE = 4
BITFIELD = 5
REQUEST = 6
PIECE = 7
CANCEL = 8

def create_handshake(info_hash, peer_id):
    """Create a BitTorrent handshake message."""
    # Convert info_hash and peer_id to bytes if strings
    if isinstance(info_hash, str):
        info_hash = bytes.fromhex(info_hash)
    if isinstance(peer_id, str):
        peer_id = peer_id.encode('utf-8')
    protocol = b'\x13BitTorrent protocol'
    reserved = b'\x00' * 8
    return protocol + reserved + info_hash + peer_id

def parse_handshake(data, expected_info_hash):
    """Parse and validate a handshake message."""
    if isinstance(expected_info_hash, str):
        expected_info_hash = bytes.fromhex(expected_info_hash)
    if len(data) < 68:
        logging.error(f"Handshake too short: {len(data)} bytes")
        return False
    if not data.startswith(b'\x13BitTorrent protocol'):
        logging.error(f"Invalid protocol identifier: {data[:19]}")
        return False
    info_hash = data[28:48]
    if info_hash != expected_info_hash:
        logging.error(f"Info hash mismatch: expected {expected_info_hash.hex()}, got {info_hash.hex()}")
        return False
    logging.debug("Handshake validated successfully")
    return True

def create_choke_message():
    """Create a choke message."""
    return struct.pack(">IB", 1, CHOKE)

def create_unchoke_message():
    """Create an unchoke message."""
    return struct.pack(">IB", 1, UNCHOKE)

def create_interested_message():
    """Create an interested message."""
    return struct.pack(">IB", 1, INTERESTED)

def create_request_message(index, begin=0, length=16384):
    """Create a request message."""
    return struct.pack(">IBIII", 13, REQUEST, index, begin, length)

def create_piece_message(index, begin, data):
    """Create a piece message."""
    length = 9 + len(data)  # 4 bytes for index, 4 bytes for begin, plus data length
    return struct.pack(">IBII", length, PIECE, index, begin) + data

def create_have_message(index):
    """Create a have message."""
    return struct.pack(">IBI", 5, HAVE, index)

def create_bitfield_message(bitfield):
    """Create a bitfield message."""
    if not isinstance(bitfield, (bytes, bytearray)):
        raise TypeError("bitfield must be bytes or bytearray")
    length = 1 + len(bitfield)  # 1 byte for message type + bitfield length
    return struct.pack(">IB", length, BITFIELD) + bitfield

def parse_message(msg):
    """Parse a BitTorrent message."""
    if len(msg) < 4:
        logging.debug(f"Message too short: {len(msg)} bytes")
        return None, None, None

    length = struct.unpack(">I", msg[:4])[0]
    logging.debug(f"Message length from header: {length}")

    if length == 0:
        logging.debug("Keep-alive message received")
        return KEEP_ALIVE, None, None

    if len(msg) < length + 4:
        logging.debug(f"Message incomplete: got {len(msg)} bytes, expected {length + 4}")
        return None, None, None

    msg_type = msg[4]
    logging.debug(f"Message type: {msg_type}")

    if msg_type == CHOKE:
        logging.debug("Choke message")
        return CHOKE, None, None
    elif msg_type == UNCHOKE:
        logging.debug("Unchoke message")
        return UNCHOKE, None, None
    elif msg_type == INTERESTED:
        logging.debug("Interested message")
        return INTERESTED, None, None
    elif msg_type == NOT_INTERESTED:
        logging.debug("Not interested message")
        return NOT_INTERESTED, None, None
    elif msg_type == HAVE:
        if len(msg) < 9:
            logging.debug("Have message too short")
            return None, None, None
        index = struct.unpack(">I", msg[5:9])[0]
        logging.debug(f"Have message for piece {index}")
        return HAVE, index, None
    elif msg_type == BITFIELD:
        bitfield = msg[5:5 + length - 1]
        logging.debug(f"Bitfield message, length: {len(bitfield)}")
        return BITFIELD, None, bitfield
    elif msg_type == REQUEST:
        if len(msg) < 17:
            logging.debug("Request message too short")
            return None, None, None
        index = struct.unpack(">I", msg[5:9])[0]
        begin = struct.unpack(">I", msg[9:13])[0]
        length = struct.unpack(">I", msg[13:17])[0]
        logging.debug(f"Request message - index: {index}, begin: {begin}, length: {length}")
        return REQUEST, index, msg[5:17]
    elif msg_type == PIECE:
        if len(msg) < 13:
            logging.debug("Piece message too short")
            return None, None, None
        index = struct.unpack(">I", msg[5:9])[0]
        begin = struct.unpack(">I", msg[9:13])[0]
        block = msg[13:13 + length - 9]
        logging.debug(f"Piece message - index: {index}, begin: {begin}, block length: {len(block)}")
        return PIECE, index, block
    elif msg_type == CANCEL:
        if len(msg) < 17:
            logging.debug("Cancel message too short")
            return None, None, None
        index = struct.unpack(">I", msg[5:9])[0]
        begin = struct.unpack(">I", msg[9:13])[0]
        length = struct.unpack(">I", msg[13:17])[0]
        logging.debug(f"Cancel message - index: {index}, begin: {begin}, length: {length}")
        return CANCEL, index, msg[5:17]
    else:
        logging.warning(f"Unknown message type: {msg_type}")
        return None, None, None