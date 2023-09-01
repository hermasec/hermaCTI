import os
import time
import hashlib
import mimetypes
import magic
import datetime

class FileAnalysis:
    def __init__(self, filePath):
        self.file_path = filePath

    def file_exists(self):
        if os.path.exists(self.file_path):
            return True
        else:
            return False

    def extract_all_data(self):
        file_data = {   "type" : self.get_file_type(),
                        "hash": self.get_hash(),
                        "size": self.get_size(),
                        "mime_type": self.get_mime_type(),
                        "architecture" : self.get_architecture(),
                        "time": {
                            "compilation" : self.get_compilation_time(),
                            "created": self.get_creation_time(),
                            "modified": self.get_modification_time()
                     }}
        return file_data

    def get_size(self):
        try:
            size = os.path.getsize(self.file_path)
            return size
        except OSError:
            return None

    def get_mime_type(self):
        mime_type, _ = mimetypes.guess_type(self.file_path)
        return mime_type

    def get_hash(self, hash_algorithm="sha256"):
        try:
            hash_func = hashlib.new(hash_algorithm)
            with open(self.file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except FileNotFoundError:
            return None

    def get_modification_time(self):
        modification_time = os.path.getmtime(self.file_path)
        return time.ctime(modification_time)

    def get_creation_time(self):
        try:
            creation_time = os.path.getctime(self.file_path)
            return time.ctime(creation_time)
        except AttributeError:
            return "Creation time not available"
        

    def get_file_type(self):
        try:
            m = magic.Magic()
            return m.from_file(self.file_path)
        except magic.MagicException:
            return "Unknown file type"

    def get_architecture(self):
        with open(self.file_path, 'rb') as file:
            magic = file.read(2)

        if magic == b'MZ':
            return 'x86 (32-bit)'
        elif magic == b'ZM':
            return 'x64 (64-bit)'
        else:
            return 'Unknown'
        
    def get_compilation_time(self):
        timestamp = os.path.getctime(self.file_path)
        time.ctime(timestamp)

        return time.ctime(timestamp)