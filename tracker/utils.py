import time

class PeerManager: 
    def __init__(self, timeout=300): 
        self.peers_by_info_hash = {} # info_hash -> list of peer dicts
        self.timeout = timeout

    def add_peer(self, info_hash, ip, port):
        # Convert info_hash to hex string for dictionary key
        if isinstance(info_hash, bytes):
            info_hash = info_hash.hex()
        
        peer = {
            "ip": ip,
            "port": port,
            "last_seen": time.time()
        }

        if info_hash not in self.peers_by_info_hash:
            self.peers_by_info_hash[info_hash] = []

        for existing in self.peers_by_info_hash[info_hash]:
            if existing["ip"] == ip and existing["port"] == port:
                existing["last_seen"] = time.time()
                return

        self.peers_by_info_hash[info_hash].append(peer)

    def get_peers(self, info_hash, exclude_ip=None, exclude_port=None):
        # Convert info_hash to hex string for dictionary key
        if isinstance(info_hash, bytes):
            info_hash = info_hash.hex()
            
        now = time.time()
        peers = self.peers_by_info_hash.get(info_hash, [])

        self.peers_by_info_hash[info_hash] = [
            peer for peer in peers if now - peer["last_seen"] < self.timeout
        ]

        filtered_peers = [
            {"ip": peer["ip"], "port": peer["port"]}
            for peer in self.peers_by_info_hash[info_hash]
            if not (peer["ip"] == exclude_ip and peer["port"] == exclude_port)
        ]

        return filtered_peers

    def remove_peer(self, info_hash, ip, port):
        # Convert info_hash to hex string for dictionary key
        if isinstance(info_hash, bytes):
            info_hash = info_hash.hex()
            
        peers = self.peers_by_info_hash.get(info_hash, [])
        self.peers_by_info_hash[info_hash] = [
            peer for peer in peers if not (peer["ip"] == ip and peer["port"] == port)
        ]

    def clear_expired_peers(self):
        now = time.time()
        for info_hash in list(self.peers_by_info_hash.keys()):
            self.peers_by_info_hash[info_hash] = [
                peer for peer in self.peers_by_info_hash[info_hash]
                if now - peer["last_seen"] < self.timeout
            ]
            if not self.peers_by_info_hash[info_hash]:
                del self.peers_by_info_hash[info_hash]
