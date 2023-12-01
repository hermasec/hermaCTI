import pymongo
from lib.Database import Database


class Recent:

    def __init__(self):

        self.db_manager = Database(database_name='mydatabase')


    def organize_data(self, limit=10):
        
        organized_data = {}
        

        last_objects = self.db_manager.find_and_sort_documents("fileinfo" , limit)
        for item in last_objects:
            sha256 = item["hash"]
            name = item["name"]

            query = {'sha256': {'$eq': sha256}}
            data = self.db_manager.find_documents('hybrid', query)

            result_dict = {}
            for item in data:
                result_dict.update(item)

            verdict = result_dict.get("verdict")
            vx_family = result_dict.get("vx_family")

            query = {'data.id': {'$eq': sha256}}
            data = self.db_manager.find_documents('virustotal', query)

            result_dict = {}
            for item in data:
                result_dict.update(item)

            malicious = result_dict["data"]["attributes"]["last_analysis_stats"]["malicious"]
            undetected = result_dict["data"]["attributes"]["last_analysis_stats"]["undetected"]


            query = {'sha256': {'$eq': sha256}}
            data = self.db_manager.find_documents("otx" , query)

            if data:
                result_dict = {}
                for item in data:
                    result_dict.update(item)

                pulses = result_dict["pulses"]
            else:
                pulses = []


            query = {'sha256': {'$eq': sha256}}
            data = self.db_manager.find_documents("intezer", query)

            if data:
                result_dict = {}
                for item in data:
                    result_dict.update(item)

                ttps = result_dict["ttps"]
            else:
                ttps = {}


            final_dict = {
                        "name" : name,
                        "verdict": verdict,
                        "vx_family": vx_family,
                        "malicious" : malicious,
                        "undetected" : undetected,
                        "pulses" : pulses,
                        "ttps" : ttps
                    }
            
            organized_data[sha256] = final_dict

        return organized_data