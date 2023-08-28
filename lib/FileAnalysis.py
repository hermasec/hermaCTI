import os
import time
import hashlib
import mimetypes


class FileAnalysis:
    def __init__(self, filePath):
        self.file_path = filePath

    def file_exists(self):
        if os.path.exists(self.file_path):
            return True
        else:
            return False

    def extract_all_data(self):
        file_data = {"size": self.get_size(),
                     "mime_type": self.get_mime_type(),
                     "hash": self.get_hash(),
                     "time": {
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