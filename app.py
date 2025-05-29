from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
import os
from werkzeug.utils import secure_filename
from torrent.torrent_creator import create_torrent
import subprocess
import threading
import shutil
from datetime import datetime
import json
import mimetypes
import magic
import hashlib
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'your-secret-key'

# Configure paths and file size limit
UPLOAD_FOLDER = 'uploads'
TORRENT_FOLDER = 'torrents'
SHARED_FOLDER = 'shared'
ALLOWED_EXTENSIONS = {
    # Text files
    'txt', 'md', 'csv', 'json', 'xml', 'html', 'css', 'js',
    # Documents
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    # Images
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp',
    # Videos
    'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm',
    # Audio
    'mp3', 'wav', 'ogg', 'flac', 'm4a',
    # Archives
    'zip', 'rar', '7z', 'tar', 'gz',
    # Code
    'py', 'java', 'cpp', 'c', 'h', 'php', 'rb', 'go'
}
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB file size limit

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['TORRENT_FOLDER'] = TORRENT_FOLDER
app.config['SHARED_FOLDER'] = SHARED_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Peer tracking system
class PeerTracker:
    def __init__(self):
        self.peers = {}  # {peer_id: {'ip': ip, 'port': port, 'files': [file_ids], 'last_seen': timestamp}}
        self.file_peers = defaultdict(set)  # {file_id: set(peer_ids)}
        self.peer_timeout = 300  # 5 minutes timeout
        self.ip_peer_map = {}  # Map IP:port to peer_id

    def add_peer(self, peer_id, ip, port, files):
        # Check if this IP:port combination already exists
        ip_port = f"{ip}:{port}"
        if ip_port in self.ip_peer_map:
            # Update existing peer
            existing_peer_id = self.ip_peer_map[ip_port]
            self.peers[existing_peer_id].update({
                'files': files,
                'last_seen': time.time()
            })
            return existing_peer_id
        
        # Add new peer
        self.peers[peer_id] = {
            'ip': ip,
            'port': port,
            'files': files,
            'last_seen': time.time()
        }
        self.ip_peer_map[ip_port] = peer_id
        
        for file_id in files:
            self.file_peers[file_id].add(peer_id)
        
        return peer_id

    def remove_peer(self, peer_id):
        if peer_id in self.peers:
            peer = self.peers[peer_id]
            ip_port = f"{peer['ip']}:{peer['port']}"
            
            # Remove from ip_peer_map
            if ip_port in self.ip_peer_map:
                del self.ip_peer_map[ip_port]
            
            # Remove from file_peers
            files = peer['files']
            for file_id in files:
                self.file_peers[file_id].discard(peer_id)
            
            # Remove from peers
            del self.peers[peer_id]

    def get_peers_for_file(self, file_id):
        return [self.peers[peer_id] for peer_id in self.file_peers[file_id] 
                if peer_id in self.peers and time.time() - self.peers[peer_id]['last_seen'] < self.peer_timeout]

    def cleanup_old_peers(self):
        current_time = time.time()
        for peer_id in list(self.peers.keys()):
            if current_time - self.peers[peer_id]['last_seen'] > self.peer_timeout:
                self.remove_peer(peer_id)

# Initialize peer tracker
peer_tracker = PeerTracker()

# Create directories if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(TORRENT_FOLDER, exist_ok=True)
os.makedirs(SHARED_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_size(file_path):
    size = os.path.getsize(file_path)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} TB"

def get_file_info(file_path):
    stats = os.stat(file_path)
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    
    # Map common MIME types to more specific categories
    mime_type_mapping = {
        # Documents
        'application/pdf': 'document/pdf',
        'application/msword': 'document/word',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'document/word',
        'application/vnd.ms-excel': 'document/excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'document/excel',
        'application/vnd.ms-powerpoint': 'document/powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'document/powerpoint',
        
        # Text files
        'text/plain': 'text/plain',
        'text/markdown': 'text/markdown',
        'text/csv': 'text/csv',
        'application/json': 'text/json',
        'text/xml': 'text/xml',
        'text/html': 'text/html',
        'text/css': 'text/css',
        'application/javascript': 'text/javascript',
        
        # Code files
        'text/x-python': 'code/python',
        'text/x-java': 'code/java',
        'text/x-c++src': 'code/cpp',
        'text/x-csrc': 'code/c',
        'text/x-php': 'code/php',
        'text/x-ruby': 'code/ruby',
        'text/x-go': 'code/go',
        
        # Archives
        'application/zip': 'archive/zip',
        'application/x-rar-compressed': 'archive/rar',
        'application/x-7z-compressed': 'archive/7z',
        'application/x-tar': 'archive/tar',
        'application/gzip': 'archive/gz'
    }
    
    # Get the mapped type or use the original MIME type
    mapped_type = mime_type_mapping.get(file_type, file_type)
    
    return {
        'size': get_file_size(file_path),
        'created': datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
        'modified': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        'type': mapped_type,
        'extension': os.path.splitext(file_path)[1].lower()
    }

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

@app.route('/')
def index():
    search_query = request.args.get('search', '').lower()
    file_type = request.args.get('type', '')
    
    files = []
    for filename in os.listdir(SHARED_FOLDER):
        file_path = os.path.join(SHARED_FOLDER, filename)
        if os.path.isfile(file_path):
            torrent_file = os.path.join(TORRENT_FOLDER, f"{filename}.torrent")
            file_info = get_file_info(file_path)
            
            # Apply search filter
            if search_query and search_query not in filename.lower():
                continue
                
            # Apply type filter
            if file_type and not file_info['type'].startswith(file_type):
                continue
            
            # Add file to peer tracker
            file_id = get_file_hash(file_path)
            if file_id not in peer_tracker.file_peers:
                peer_tracker.file_peers[file_id] = set()
            
            files.append({
                'name': filename,
                'size': file_info['size'],
                'created': file_info['created'],
                'modified': file_info['modified'],
                'type': file_info['type'],
                'extension': file_info['extension'],
                'has_torrent': os.path.exists(torrent_file),
                'status': 'Ready' if os.path.exists(torrent_file) else 'Processing',
                'file_id': file_id  # Add file_id to the file info
            })
    
    # Sort files by modification date (newest first)
    files.sort(key=lambda x: x['modified'], reverse=True)
    
    return render_template('index.html', 
                         files=files, 
                         search_query=search_query,
                         file_type=file_type)

@app.route('/preview/<filename>')
def preview_file(filename):
    file_path = os.path.join(SHARED_FOLDER, filename)
    if not os.path.exists(file_path):
        flash('File not found')
        return redirect(url_for('index'))
    
    file_info = get_file_info(file_path)
    mime_type = file_info['type']
    
    # For images, PDFs, and videos, return the file directly
    if mime_type.startswith(('image/', 'application/pdf', 'video/')):
        return send_file(file_path, mimetype=mime_type)
    
    # For text files, read and return content
    if mime_type.startswith('text/'):
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return render_template('preview.html', filename=filename, content=content)
    
    # For other files, return metadata
    return render_template('preview.html', filename=filename, file_info=file_info)

@app.route('/metadata/<filename>')
def get_metadata(filename):
    file_path = os.path.join(SHARED_FOLDER, filename)
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    file_info = get_file_info(file_path)
    return jsonify(file_info)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))

    if file and allowed_file(file.filename):
        try:
            filename = secure_filename(file.filename)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            shared_path = os.path.join(app.config['SHARED_FOLDER'], filename)
            torrent_path = os.path.join(app.config['TORRENT_FOLDER'], f"{filename}.torrent")

            # Save temporarily to check file
            file.save(temp_path)
            
            # Get file size and hash
            new_file_size = os.path.getsize(temp_path)
            new_file_hash = get_file_hash(temp_path)

            # Check if file already exists with same size and hash
            if os.path.exists(shared_path):
                existing_file_size = os.path.getsize(shared_path)
                existing_file_hash = get_file_hash(shared_path)
                
                if new_file_size == existing_file_size and new_file_hash == existing_file_hash:
                    os.remove(temp_path)  # Remove temporary file
                    flash(f'File "{filename}" already exists with the same content')
                    return redirect(url_for('index'))

            # Validate file size
            if new_file_size > MAX_CONTENT_LENGTH:
                os.remove(temp_path)
                flash('File size exceeds limit')
                return redirect(url_for('index'))

            # Create torrent
            create_torrent(temp_path, "http://localhost:5001/announce", torrent_path)
            
            # Move to shared folder
            shutil.move(temp_path, shared_path)
            
            flash(f'File uploaded successfully as: {filename}')
            return redirect(url_for('index'))

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            flash(f'Error processing file: {str(e)}')
            return redirect(url_for('index'))

    flash('File type not allowed')
    return redirect(url_for('index'))

@app.route('/start_sharing/<filename>')
def start_sharing(filename):
    torrent_path = os.path.join(TORRENT_FOLDER, f"{filename}.torrent")

    def run_uploader():
        subprocess.run(['python3', '-m', 'client.uploader', torrent_path])

    thread = threading.Thread(target=run_uploader)
    thread.daemon = True
    thread.start()

    flash('Started sharing the file')
    return redirect(url_for('index'))

@app.route('/start_downloading/<filename>')
def start_downloading(filename):
    file_path = os.path.join(SHARED_FOLDER, filename)

    if not os.path.exists(file_path):
        flash('File not found')
        return redirect(url_for('index'))

    try:
        # Add file to active peers
        if filename not in peer_tracker.peers:
            peer_tracker.peers[filename] = {}

        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype=magic.Magic(mime=True).from_file(file_path)
        )
    except Exception as e:
        flash(f'Error downloading file: {str(e)}')
        return redirect(url_for('index'))
    finally:
        # Remove from active peers after download
        if filename in peer_tracker.peers:
            del peer_tracker.peers[filename]

@app.route('/delete/<filename>')
def delete_file(filename):
    try:
        file_path = os.path.join(SHARED_FOLDER, filename)
        torrent_path = os.path.join(TORRENT_FOLDER, f"{filename}.torrent")

        if not os.path.exists(file_path):
            flash('File not found')
            return redirect(url_for('index'))

        # Check if file is being downloaded
        if filename in peer_tracker.peers:
            flash('Cannot delete file while it is being downloaded')
            return redirect(url_for('index'))

        if os.path.exists(file_path):
            os.remove(file_path)
        if os.path.exists(torrent_path):
            os.remove(torrent_path)
        
        flash('File deleted successfully')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}')

    return redirect(url_for('index'))

@app.route('/announce', methods=['GET', 'POST'])
def announce():
    """Handle tracker announce requests."""
    try:
        if request.method == 'POST':
            data = request.get_json()
        else:
            data = request.args.to_dict()

        info_hash = data.get('info_hash')
        if not info_hash:
            return jsonify({'error': 'Missing info_hash'}), 400

        peer = {
            'ip': data.get('ip', request.remote_addr),
            'port': int(data.get('port', 6881)),
            'uploaded': int(data.get('uploaded', 0)),
            'downloaded': int(data.get('downloaded', 0)),
            'left': int(data.get('left', 0)),
            'event': data.get('event', 'started')
        }

        # Update peer list
        if info_hash not in peer_tracker.peers:
            peer_tracker.peers[info_hash] = {}
        
        peer_id = f"{peer['ip']}:{peer['port']}"
        peer_tracker.peers[info_hash][peer_id] = peer

        # Clean up inactive peers (older than 30 minutes)
        peer_tracker.cleanup_old_peers()

        # Update last seen time
        peer['last_seen'] = time.time()
        peer_tracker.peers[info_hash][peer_id] = peer

        # Return list of peers
        peers = list(peer_tracker.peers[info_hash].values())
        return jsonify({
            'peers': peers,
            'interval': 1800,  # 30 minutes
            'min_interval': 900,  # 15 minutes
            'complete': len([p for p in peers if p['left'] == 0]),
            'incomplete': len([p for p in peers if p['left'] > 0])
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/register_peer', methods=['POST'])
def register_peer():
    data = request.json
    peer_id = data.get('peer_id')
    ip = request.remote_addr
    port = data.get('port')
    files = data.get('files', [])
    
    if not all([peer_id, port]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    actual_peer_id = peer_tracker.add_peer(peer_id, ip, port, files)
    return jsonify({
        'status': 'success',
        'peer_id': actual_peer_id
    })

@app.route('/get_peers/<file_id>', methods=['GET'])
def get_peers(file_id):
    peer_tracker.cleanup_old_peers()
    peers = peer_tracker.get_peers_for_file(file_id)
    return jsonify({'peers': peers})

@app.route('/heartbeat', methods=['POST'])
def peer_heartbeat():
    data = request.json
    peer_id = data.get('peer_id')
    files = data.get('files', [])
    
    if not peer_id:
        return jsonify({'error': 'Missing peer_id'}), 400
    
    if peer_id in peer_tracker.peers:
        peer_tracker.peers[peer_id]['last_seen'] = time.time()
        peer_tracker.peers[peer_id]['files'] = files
        return jsonify({'status': 'success'})
    
    return jsonify({'error': 'Peer not found'}), 404

@app.route('/get_peers/all', methods=['GET'])
def get_all_peers():
    peer_tracker.cleanup_old_peers()
    return jsonify({
        'peers': list(peer_tracker.peers.values()),
        'files': list(peer_tracker.file_peers.keys())
    })

