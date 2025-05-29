import socket
import struct
import logging
import time

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")

class PeerConnection:
    def __init__(self, ip, port, timeout=5):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.connected = False

    def connect(self):
        """Establish a TCP connection to the peer."""
        if self.connected:
            return True
            
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect((self.ip, self.port))
            self.connected = True
            logging.info(f"Connected to peer at {self.ip}:{self.port}")
            return True
        except Exception as e:
            logging.error(f"Could not connect to peer at {self.ip}:{self.port}: {e}")
            self.sock = None
            self.connected = False
            return False

    def send(self, data):
        """Send raw bytes to the connected peer."""
        if not self.sock or not self.connected:
            logging.error(f"No socket to send to {self.ip}:{self.port}")
            raise ValueError("No socket")
        try:
            self.sock.sendall(data)
            logging.debug(f"Sent {len(data)} bytes to {self.ip}:{self.port}")
        except Exception as e:
            logging.error(f"Failed to send data to {self.ip}:{self.port}: {e}")
            self.connected = False
            raise

    def receive(self, buffer_size=4096):
        """Receive a single BitTorrent message with length prefix."""
        if not self.sock or not self.connected:
            return None
        try:
            # Read length prefix (4 bytes)
            length_data = self.receive_exact(4)
            if not length_data:
                logging.debug(f"Connection closed by {self.ip}:{self.port}")
                self.connected = False
                return None
            length = struct.unpack(">I", length_data)[0]

            # Read the full message
            data = self.receive_exact(length)
            if not data:
                logging.error(f"Incomplete message from {self.ip}:{self.port}")
                self.connected = False
                return None
            logging.debug(f"Received {len(data) + 4} bytes from {self.ip}:{self.port}")
            return length_data + data
        except Exception as e:
            logging.error(f"Error receiving data from {self.ip}:{self.port}: {e}")
            self.connected = False
            return None

    def receive_exact(self, size):
        """Receive exactly 'size' bytes from the socket."""
        if not self.sock or not self.connected:
            return None
            
        data = b""
        start_time = time.time()
        
        while len(data) < size:
            if time.time() - start_time > self.timeout:
                logging.error(f"Timeout receiving data from {self.ip}:{self.port}")
                self.connected = False
                return None
                
            try:
                chunk = self.sock.recv(min(size - len(data), 4096))
                if not chunk:
                    self.connected = False
                    return None
                data += chunk
            except socket.timeout:
                logging.error(f"Socket timeout receiving data from {self.ip}:{self.port}")
                self.connected = False
                return None
            except Exception as e:
                logging.error(f"Error receiving data from {self.ip}:{self.port}: {e}")
                self.connected = False
                return None
                
        return data

    def close(self):
        """Close the socket connection to the peer."""
        if self.sock:
            try:
                self.sock.close()
                logging.debug(f"Connection to {self.ip}:{self.port} closed")
            except Exception as e:
                logging.error(f"Error closing connection to {self.ip}:{self.port}: {e}")
            self.sock = None
            self.connected = False