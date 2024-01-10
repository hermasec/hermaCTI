import os
from datetime import datetime
import humanize
from bson import ObjectId
from lib.Database import Database
from lib.FileAnalysis import FileAnalysis
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.api.OTX import OTX


class Filter:

    def __init__(self):
        self.db_manager = Database(database_name='mydatabase')
        self.virustotal = Virustotal(os.environ.get("VIRUSTOTAL_API_TOKEN"))
        self.hybrid = Hybrid(os.environ.get("HYBRID_API_TOKEN"))
        self.otx = OTX(os.environ.get("OTX_API_TOKEN"))
        self.file = FileAnalysis()

    def get_hash_data(self, hash, from_module):
        fileinfo = {}
        hybrid_data = self.hybrid.get_desired_data(hash)
        virustotal_data = self.virustotal.get_desired_data(hash)
        otx_data = self.otx.get_desired_data(hash)
        virustotal_ttps = self.virustotal.get_ttps(hash) if from_module == "stix" else self.filter_virustotal_ttps_data(
            self.virustotal.get_ttps(hash))

        if "error" in hybrid_data or "error" in virustotal_data:
            return {"error": "error in returning hybrid and virustotal data"}
        else:
            query = {'sha256': {'$eq': hash}}
            data = self.db_manager.find_documents('fileinfo', query)
            if data:
                for item in data:
                    if '_id' in item and isinstance(item['_id'], ObjectId):
                        del item['_id']
                    fileinfo.update(item)
            else:
                query = {'data.id': {'$eq': hash}}
                vt_data = self.db_manager.find_documents('virustotal', query)
                result_dict = {}
                for item in vt_data:
                    if '_id' in item and isinstance(item['_id'], ObjectId):
                        del item['_id']
                    result_dict.update(item)
                fileinfo = self.add_fileinfo_from_virustotal(result_dict)

            AVs_data = hybrid_data["AVs"]
            AVs_data.update(virustotal_data)
            file_status = "clean" if hybrid_data["verdict"] == "no specific threat" else hybrid_data["verdict"]
            file_family = hybrid_data["vx_family"]

            if virustotal_ttps:
                has_TTP = True
            elif otx_data:
                has_TTP = True if otx_data[0]["TTPs"] else False
            else:
                has_TTP = False

            if otx_data:
                has_IOC = True if otx_data[0]["IOCs"] else False
            else:
                has_IOC = False

            return_data = {
                "sha256": hash,
                "fileinfo": fileinfo,
                "file_status": file_status,
                "family": file_family,
                "has_IOC": has_IOC,
                "has_TTP": has_TTP,
                "AVs": AVs_data,
                "Attacks": otx_data,
                "TTPs": virustotal_ttps
            }

        return return_data

    def filter_virustotal_ttps_data(self, data):
        techniques_ids = []

        for tool_name, tool_data in data["data"].items():
            for tactic_data in tool_data["tactics"]:
                for technique_data in tactic_data["techniques"]:
                    technique_id = technique_data["id"]
                    techniques_ids.append(technique_id)

        unique_techniques_ids = list(set(techniques_ids))

        return unique_techniques_ids

    def add_fileinfo_from_virustotal(self, all_json):
        names = all_json['data']['attributes']['names']

        if len(names) > 0:
            name = all_json['data']['attributes']['names'][0]
        else:
            name = None

        if 'pe_info' in all_json['data']['attributes']:
            compiledata = self.transfer_time(all_json['data']['attributes']['pe_info']['timestamp'])
        else:
            compiledata = None

        if 'creation_date' in all_json['data']['attributes']:
            creationdata = self.transfer_time(all_json['data']['attributes']['creation_date'])
        else:
            creationdata = None

        if 'last_modification_date' in all_json['data']['attributes']:
            modificationdate = self.transfer_time(all_json['data']['attributes']['last_modification_date'])
        else:
            modificationdate = None

        if 'type_extension' in all_json['data']['attributes']:
            extension = all_json['data']['attributes']['type_extension']
        elif 'type_tag' in all_json['data']['attributes']:
            extension = all_json['data']['attributes']['type_tag']
        else:
            extension = None

        file_data = {
            "name": name,
            "file_extension": extension,
            "type": all_json['data']['attributes']['magic'],
            "scan_date": datetime.now(),
            "sha256": all_json['data']['attributes']['sha256'],
            "md5": all_json['data']['attributes']['md5'],
            "size": humanize.naturalsize(all_json['data']['attributes']['size']),
            "time": {
                "compilation": compiledata,
                "created": creationdata,
                "modified": modificationdate
            }
        }

        inserted_id = self.db_manager.insert_document('fileinfo', file_data)
        result_dict = {}
        if '_id' in file_data and isinstance(file_data['_id'], ObjectId):
            del file_data['_id']
        result_dict.update(file_data)
        return result_dict

    def transfer_time(self, timestamp):
        formatted_date = datetime.fromtimestamp(timestamp).strftime("%a %b %d %H:%M:%S %Y")
        return formatted_date

    def get_last_scans(self, limit=10):
        last_objects = self.db_manager.find_and_sort_documents("fileinfo", "scan_date", limit)
        result_list = []
        for item in last_objects:
            sha256 = item["sha256"]
            all_data = self.get_hash_data(sha256)
            required_data = {
                "name": all_data["fileinfo"]["name"],
                "sha256": all_data["sha256"],
                "type": all_data["fileinfo"]["file_extension"],
                "file_status": all_data["file_status"],
                "has_IOC": all_data["has_IOC"],
                "has_TTP": all_data["has_TTP"],
                "scan_date": all_data["fileinfo"]["scan_date"]
            }
            result_list.append(required_data)
        return result_list
