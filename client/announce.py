import urllib.parse
import urllib.request
import logging
import json
import time
import os

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        # Create a socket connection to get the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def announce_to_tracker(torrent, port, num_want=50):
    """Announce to the tracker and get a list of peers."""
    params = {
        'info_hash': torrent.info_hash.hex(),
        'peer_id': '-PY0001-' + os.urandom(12).hex(),
        'port': port,
        'uploaded': 0,
        'downloaded': 0,
        'left': torrent.length,
        'num_want': num_want,
        'compact': 1
    }

    # Update tracker URL to use port 5001
    tracker_url = torrent.announce.replace(':5000', ':5001')
    url = f"{tracker_url}?{urllib.parse.urlencode(params)}"
    
    logging.info(f"Announcing to tracker...")
    logging.debug(f"URL: {url}")

    max_retries = 3
    retry_delay = 1  # seconds

    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(url) as response:
                data = json.loads(response.read().decode())
                peers = data.get('peers', [])
                logging.info(f"Received {len(peers)} peers from tracker")
                return peers
        except Exception as e:
            if attempt < max_retries - 1:
                logging.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                logging.error(f"Failed to connect to tracker after {max_retries} attempts: {e}")
                return []
