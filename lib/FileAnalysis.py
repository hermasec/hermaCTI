import os
import time
import hashlib
from datetime import datetime
import magic
import humanize
from lib.Database import Database


class FileAnalysis:
    def __init__(self):
        self.db_manager = Database(database_name='mydatabase')


    def file_exists(self, filePath):
        if os.path.exists(filePath):
            return True
        else:
            return False

    def get_uploaded_fileinfo(self, filePath):
        result_dict = {}
        if self.file_exists(filePath):

            query = {'sha256': {'$eq': self.get_sha256(filePath)}}
            data = self.db_manager.find_documents('fileinfo', query)

            if data:
                result_dict = data[0]
            else:
                data = self.gather_all_data(filePath)
                self.db_manager.insert_document('fileinfo', data)
                result_dict = data
        else:
            result_dict = {"error": "file_not_found"}


        return result_dict





    def gather_all_data(self, filePath):

        file_data = {"name": self.get_name(filePath),
                     "file_extension": self.get_extension(filePath),
                     "type": self.get_file_type(filePath),
                     "scan_date": datetime.now(),
                     "sha256": self.get_sha256(filePath),
                     "md5": self.get_md5(filePath),
                     "size": self.get_size(filePath),
                     "time": {
                         "compilation": self.get_compilation_time(filePath),
                         "created": self.get_creation_time(filePath),
                         "modified": self.get_modification_time(filePath)
                     }
                }

        return file_data

    def get_size(self, filePath):
        try:
            size = os.path.getsize(filePath)
            return humanize.naturalsize(size)
        except OSError:
            return None

    def get_extension(self, filePath):
        try:
            _, file_extension = os.path.splitext(filePath)
            return file_extension[1:]
        except OSError:
            return None


    def get_name(self, filePath):
        try:
            file_name = os.path.basename(filePath)
            return file_name
        except OSError:
            return None

    def get_sha256(self, filePath):
        try:
            hash_func = hashlib.new("sha256")
            with open(filePath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except FileNotFoundError:
            return None

    def get_md5(self, filePath ):
        md5_hash = hashlib.md5()
        with open(filePath, 'rb') as file:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: file.read(4096), b''):
                md5_hash.update(chunk)
        return md5_hash.hexdigest()

    def get_modification_time(self, filePath):
        modification_time = os.path.getmtime(filePath)
        return time.ctime(modification_time)

    def get_creation_time(self , filePath):
        try:
            creation_time = os.path.getctime(filePath)
            return time.ctime(creation_time)
        except AttributeError:
            return "Creation time not available"

    def get_file_type(self , filePath):
        try:
            m = magic.Magic()
            return m.from_file(filePath)
        except magic.MagicException:
            return "Unknown file type"

    def get_architecture(self,filePath):
        with open(filePath, 'rb') as file:
            magic = file.read(2)

        if magic == b'MZ':
            return 'x86 (32-bit)'
        elif magic == b'ZM':
            return 'x64 (64-bit)'
        else:
            return 'Unknown'

    def get_compilation_time(self, filePath):
        timestamp = os.path.getctime(filePath)
        time.ctime(timestamp)

        return time.ctime(timestamp)

