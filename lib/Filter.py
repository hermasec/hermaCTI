import base64
import os
from collections import Counter
from datetime import datetime
import humanize
from flask import jsonify
from lib.Charts import Charts
from lib.Database import Database
from lib.SIEM import SIEM
from lib.TAXII import TAXII
from lib.Yara import Yara
from lib.api.Virustotal import Virustotal
from lib.api.Hybrid import Hybrid
from lib.api.OTX import OTX
import shutil


class Filter:

    def __init__(self):
        self.db_manager = Database(database_name='mydatabase')
        self.virustotal = Virustotal(os.environ.get("VIRUSTOTAL_API_TOKEN"))
        self.hybrid = Hybrid(os.environ.get("HYBRID_API_TOKEN"))
        self.otx = OTX(os.environ.get("OTX_API_TOKEN"))
        self.yara = Yara()
        self.siem = SIEM()
        self.taxii = TAXII()

    def get_hash_data(self, hash):
        fileinfo = {}
        hybrid_data = self.hybrid.get_desired_data(hash)
        virustotal_data = self.virustotal.get_desired_data(hash)

        virustotal_ttps_for_stix = {}
        virustotal_ttps = self.virustotal.get_ttps(hash)
        if virustotal_ttps == {} or "error" in virustotal_ttps:
            virustotal_ttps = {}
        else:
            virustotal_ttps_for_stix = self.virustotal.get_ttps(hash)
            virustotal_ttps = self.filter_virustotal_ttps_data(self.virustotal.get_ttps(hash))

        if "error" in hybrid_data:
            hybrid_data = {}

        if "error" in virustotal_data:
            virustotal_data = {}

        query = {'sha256': {'$eq': hash}}
        data = self.db_manager.find_documents('fileinfo', query)
        if data:
            fileinfo = data[0]
        else:
            query = {'data.id': {'$eq': hash}}
            vt_data = self.db_manager.find_documents('virustotal', query)
            if vt_data:
                fileinfo = self.add_fileinfo_from_virustotal(vt_data[0])
            else:
                return jsonify({"error": "No specific information for this hash"}), 404

        file_family, file_status = "", ""
        AVs_data = {}
        if hybrid_data:
            AVs_data.update(hybrid_data["AVs"])
            file_status = "clean" if hybrid_data["verdict"] == "no specific threat" else hybrid_data["verdict"]
            file_family = hybrid_data["vx_family"]
        if virustotal_data:
            AVs_data.update(virustotal_data["AVs"])

        if hybrid_data == {} and virustotal_data:
            file_family = virustotal_data["family"]
            file_status = virustotal_data["status"]

        if file_status == "malicious":
            otx_data = self.otx.get_desired_data(hash)
        else:
            otx_data = []

        return_data_for_stix = {
            "sha256": hash,
            "fileinfo": fileinfo,
            "file_status": file_status,
            "family": file_family,
            "AVs": AVs_data,
            "Attacks": otx_data,
            "TTPs": virustotal_ttps_for_stix
        }

        if file_status == "malicious":
            self.taxii.add_objects_to_collection(hash, "91a7b528-80eb-42ed-a74d-c6fbd5a26116", return_data_for_stix)

        return_data = {
            "sha256": hash,
            "fileinfo": fileinfo,
            "file_status": file_status,
            "family": file_family,
            "AVs": AVs_data,
            "Attacks": otx_data,
            "TTPs": virustotal_ttps,
        }

        if file_status == "malicious":
            zip_base64 = self.get_base64_zip_rules(hash, return_data)
            if zip_base64:
                return_data["zip_rules"] = zip_base64

        fileinfo["size"] = humanize.naturalsize(fileinfo["size"])
        return return_data

    def get_base64_zip_rules(self, hash, all_data):
        query = {'sha256': {'$eq': hash}}
        data = self.db_manager.find_documents('rules', query)

        if data:
            return data[0]["zip_rules"]
        else:
            yara_generated_file = self.yara.yara_generator(all_data["fileinfo"]["size"], hash)
            sigma_rule_file = self.siem.get_sigma_rule(all_data)
            yara_scanners_rules = ".\\rules\\scanners_yara_rules.yar"

            try:
                # Create a temporary zip file
                temp_zip_file = 'temp_rules.zip'
                shutil.make_archive(temp_zip_file[:-4], 'zip', ".\\rules")

                # Read the zip file as binary and encode it to base64
                with open(temp_zip_file, 'rb') as zip_file:
                    base64_encoded_zip = base64.b64encode(zip_file.read())

                # Delete the temporary zip file
                os.remove(temp_zip_file)
                os.remove(yara_generated_file)
                if sigma_rule_file:
                    os.remove(sigma_rule_file)
                if os.path.exists(yara_scanners_rules):
                    os.remove(yara_scanners_rules)

                zip_base64 = base64_encoded_zip.decode()
                result_dict = {
                    "sha256": hash,
                    "zip_rules": zip_base64
                }
                self.db_manager.insert_document('rules', result_dict)
                return zip_base64

            except Exception as e:
                print(f"Error zipping directory and converting to base64: {e}")
                return None

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

        if 'magic' in all_json['data']['attributes']:
            type = all_json['data']['attributes']['magic']
        else:
            type = None

        file_data = {
            "name": name,
            "file_extension": extension,
            "type": type,
            "scan_date": datetime.now(),
            "sha256": all_json['data']['attributes']['sha256'],
            "md5": all_json['data']['attributes']['md5'],
            "size": all_json['data']['attributes']['size'],
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

        if hybrid_data == [] and virustotal_data:
            malicious = virustotal_data[0]["data"]["attributes"]["last_analysis_stats"]["malicious"]
            undetected = virustotal_data[0]["data"]["attributes"]["last_analysis_stats"]["undetected"]
            clean = virustotal_data[0]["data"]["attributes"]["last_analysis_stats"]["harmless"]
            if malicious > undetected and malicious > clean:
                file_status = "malicious"
            elif undetected > malicious or clean > malicious:
                file_status = "clean"
            else:
                file_status = "no-result"

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

    def get_last_attack_indicators(self, limit=10):
        last_objects = self.db_manager.find_and_sort_documents("fileinfo", "scan_date", limit)
        result_dict = {}
        for item in last_objects:
            sha256 = item["sha256"]
            all_data = self.get_attack_chart_data(sha256)
            if all_data is not None:
                for data in all_data:
                    if data:
                        result_dict.update(data)
        return result_dict

    def get_attack_chart_data(self, hash):
        query = {'sha256': {'$eq': hash}}

        result_list = []
        otx_data = self.db_manager.find_documents('otx', query)
        if otx_data:
            for pulse in otx_data[0]["pulses"]:
                attack_name = pulse["name"]
                indicators = pulse["indicators"]

                filtered_indicators = []
                for index, item in enumerate(indicators):
                    if index >= 150:
                        break
                    filtered_indicators.append({"indicator": item["indicator"], "type": item["type"]})

                dic = {
                    "attack_name": attack_name,
                    "IOCs": filtered_indicators
                }
                result_list.append(dic)

            charts = Charts()
            indicators_percentage = charts.extract_indicators_percentages(result_list)

            return indicators_percentage

    def most_ttps_used(self, hash):

        query = {'data.id': {'$eq': hash}}
        data = self.db_manager.find_documents('virustotal', query)

        if data:
            if 'mitre' in data[0]:
                virustotal_ttps = data[0]["mitre"]
            else:
                virustotal_ttps = {}
        else:
            virustotal_ttps = {}

        if virustotal_ttps == {} or "error" in virustotal_ttps:
            virustotal_ttps = []
        else:
            virustotal_ttps = self.filter_virustotal_ttps_data(virustotal_ttps)

        return virustotal_ttps

    def get_last_most_ttps(self, limit=10):
        last_objects = self.db_manager.find_and_sort_documents("fileinfo", "scan_date", limit)
        result_list = []
        for item in last_objects:
            sha256 = item["sha256"]
            all_data = self.most_ttps_used(sha256)
            if all_data is not None:
                for data in all_data:
                    if data:
                        result_list.append(data)

        element_counts = Counter(result_list)
        most_common_ttps = element_counts.most_common(4)
        result_dict = {name: value for name, value in most_common_ttps}
        return result_dict

    def get_every_scan_per_day(self):

        result = self.db_manager.get_scans_per_day('fileinfo')

        result_json = {
            "results": result
        }

        return result_json
