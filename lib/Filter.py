import os
from datetime import datetime
import humanize
from lib.Database import Database
from lib.FileAnalysis import FileAnalysis
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.api.OTX import OTX
from lib.api.STIX import STIX


class Filter:

    def __init__(self):
        self.db_manager = Database(database_name='mydatabase')
        self.virustotal = Virustotal(os.environ.get("VIRUSTOTAL_API_TOKEN"))
        self.hybrid = Hybrid(os.environ.get("HYBRID_API_TOKEN"))
        self.otx = OTX(os.environ.get("OTX_API_TOKEN"))
        self.file = FileAnalysis()

    def get_hash_data(self, hash):
        fileinfo = {}
        hybrid_data = self.hybrid.get_desired_data(hash)
        virustotal_data = self.virustotal.get_desired_data(hash)
        otx_data = self.otx.get_desired_data(hash)
        if self.virustotal.get_ttps(hash) == {}:
            virustotal_ttps = {}
        else:
            virustotal_ttps_for_stix = self.virustotal.get_ttps(hash)
            virustotal_ttps = self.filter_virustotal_ttps_data(self.virustotal.get_ttps(hash))

        if "error" in hybrid_data or "error" in virustotal_data:
            return {"error": "error in returning hybrid and virustotal data"}
        else:
            query = {'sha256': {'$eq': hash}}
            data = self.db_manager.find_documents('fileinfo', query)
            if data:
                fileinfo = data[0]
            else:
                query = {'data.id': {'$eq': hash}}
                vt_data = self.db_manager.find_documents('virustotal', query)
                fileinfo = self.add_fileinfo_from_virustotal(vt_data[0])

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

            return_data_for_stix = {
                "sha256": hash,
                "fileinfo": fileinfo,
                "file_status": file_status,
                "family": file_family,
                "has_IOC": has_IOC,
                "has_TTP": has_TTP,
                "AVs": AVs_data,
                "Attacks": otx_data,
                "TTPs": virustotal_ttps_for_stix
            }

        # self.add_stix(return_data_for_stix)

        return return_data


    def add_stix(self, data):
        stix = STIX()
        stix_bundle = stix.all_stix_data(data)
        stix_json = stix_bundle.serialize(pretty=True)
        with open("output.json", "w") as json_file:
            json_file.write(stix_json)

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

        self.db_manager.insert_document('fileinfo', file_data)
        return file_data

    def transfer_time(self, timestamp):
        formatted_date = datetime.fromtimestamp(timestamp).strftime("%a %b %d %H:%M:%S %Y")
        return formatted_date

    def get_short_hash_data(self, hash):
        query = {'sha256': {'$eq': hash}}

        fileinfo = self.db_manager.find_documents('fileinfo', query)
        if fileinfo:
            name = fileinfo[0]["name"]
            sha256 = fileinfo[0]["sha256"]
            file_extension = fileinfo[0]["file_extension"]
            scan_date = fileinfo[0]["scan_date"]

        hybrid_data = self.db_manager.find_documents('hybrid', query)
        if hybrid_data:
            file_status = "clean" if hybrid_data[0]["verdict"] == "no specific threat" else hybrid_data[0]["verdict"]

        otx_data = self.db_manager.find_documents('otx', query)

        has_IOC, has_TTP = False, False
        if otx_data:
            for pulse in otx_data[0]["pulses"]:
                has_IOC = True if pulse["indicators"] else False
                has_TTP = True if pulse["attack_ids"] else False
                if has_IOC == True and has_TTP == True:
                    break

        query = {'data.id': {'$eq': hash}}
        virustotal_data = self.db_manager.find_documents('virustotal', query)
        if virustotal_data:
            if 'mitre' in virustotal_data[0]:
                has_TTP = True

        required_data = {
            "name": name,
            "sha256": sha256,
            "type": file_extension,
            "file_status": file_status,
            "has_IOC": has_IOC,
            "has_TTP": has_TTP,
            "scan_date": scan_date
        }
        return required_data

    def get_last_scans(self, limit=10):
        last_objects = self.db_manager.find_and_sort_documents("fileinfo", "scan_date", limit)
        result_list = []
        for item in last_objects:
            sha256 = item["sha256"]
            all_data = self.get_short_hash_data(sha256)
            result_list.append(all_data)
        return result_list