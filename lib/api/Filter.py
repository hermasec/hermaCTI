import os
from datetime import datetime

import humanize
import requests
from bson import ObjectId
from flask import jsonify

from lib.Database import Database
from lib.FileAnalysis import FileAnalysis
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.api.OTX import OTX


class Threats:

    def __init__(self, hash):
        self.hash = hash
        self.db_manager = Database(database_name='mydatabase')
        self.virustotal = Virustotal(os.environ.get("VIRUSTOTAL_API_TOKEN"))
        self.hybrid = Hybrid(os.environ.get("HYBRID_API_TOKEN"))
        self.otx = OTX(os.environ.get("OTX_API_TOKEN"))
        self.file = FileAnalysis()

    def get_all_data(self):

        hybrid_data = self.hybrid.get_desired_data(self.hash)
        virustotal_data = self.virustotal.get_desired_data(self.hash)
        if "error" in hybrid_data or "error" in virustotal_data:
            return {"error": "error in returning hybrid and virustotal data"}
        else:
            query = {'hash': {'$eq': self.hash}}
            data = self.db_manager.find_documents('fileinfo', query)
            if data:
                fileinfo = {}
                for item in data:
                    if '_id' in item and isinstance(item['_id'], ObjectId):
                        del item['_id']
                    fileinfo.update(item)
            else:
                query = {'data.id': {'$eq': self.hash}}
                data = self.db_manager.find_documents('virustotal', query)
                result_dict = {}
                for item in data:
                    if '_id' in item and isinstance(item['_id'], ObjectId):
                        del item['_id']
                    result_dict.update(item)

                fileinfo = self.get_fileinfo(result_dict)

            AVs_data=hybrid_data["AVs"]
            AVs_data.update(virustotal_data)

            data = {
                "sha256" : self.hash,
                "info": fileinfo,
                "AVs": AVs_data,
                "Attacks" : self.otx.get_desired_data(self.hash)
            }

            return data

    def get_fileinfo(self, all_json):
        file_data = {
                "name": all_json['data']['attributes']['names'][0],
                "type": all_json['data']['attributes']['magic'],
                "hash": all_json['data']['attributes']['sha256'],
                "size": humanize.naturalsize(all_json['data']['attributes']['size']),
                "time": {
                     "compilation": self.transfer_time(all_json['data']['attributes']['pe_info']['timestamp']),
                     "created": self.transfer_time(all_json['data']['attributes']['creation_date']),
                     "modified": self.transfer_time(all_json['data']['attributes']['last_modification_date'])
                 }}
        inserted_id = self.db_manager.insert_document('fileinfo', file_data)
        result_dict = {}
        if '_id' in file_data and isinstance(file_data['_id'], ObjectId):
            del file_data['_id']
        result_dict.update(file_data)
        return result_dict

    def transfer_time(self,timestamp):
        formatted_date =datetime.fromtimestamp(timestamp).strftime("%a %b %d %H:%M:%S %Y")
        return formatted_date



# tr = Threats("1a1c5cfc2a24ba5eaa67035d1ca2b5d954597de7dda0154eaef8f66d537672b0")
# res = tr.get_info()
# print(res)



