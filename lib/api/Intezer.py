import requests
import json
import time
from lib.Database import Database


class Intezer:

    def __init__(self, api_key):
        self.Auth_token = ""
        self.api_key = api_key
        self.base_url = 'https://analyze.intezer.com/api/v2-0'
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
        self.db_manager = Database(database_name='mydatabase')


    def get_desired_data(self , hash):

        query = {'sha256': {'$eq': hash}}
        data = self.db_manager.find_documents('intezer', query)
        

        result_dict = {}

        if data:
            for item in data:
                result_dict.update(item)
            
        else:
            result_dict = self.search_sha256(hash)
            
            if "error" in result_dict:
                pass
            else:
                self.db_manager.insert_document('intezer', result_dict)

        return result_dict

    def get_jwt(self):

        url = f'{self.base_url}/get-access-token'

        data = {
            "api_key": self.api_key
        }

        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(data))
            response.raise_for_status()

            if response.status_code == 200 or 201:
                self.Auth_token = response.json()['result']
                return self.Auth_token
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
        

    def search_sha256(self,sha256_value):
        self.get_jwt()

        url = f'{self.base_url}/analyze-by-hash'

        data = {
            "hash": sha256_value,
            "code_item_type": "file",
            "disable_dynamic_execution": False,
            "disable_static_extraction": False,
            "sandbox_command_line_arguments": "string"
        }

        self.headers['Authorization'] = 'Bearer ' + self.Auth_token

        try:
            response = requests.post(url, headers=self.headers, data=json.dumps(data))
            response.raise_for_status()

            if response.status_code == 200 or 201:
                result_url = response.json()['result_url']
                time.sleep(24)
                return self.get_ttps(result_url , sha256_value)
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
        

    def get_ttps(self,result_url , sha256_value):

        url = f'{self.base_url}{result_url}/dynamic-ttps'
        self.headers['Authorization'] = 'Bearer ' + self.Auth_token

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            if response.status_code == 200 or 201:
                all_ttps = []
                ttps_dict = {}

                data = response.json()
                for entry in data["result"]:
                    if "ttps" in entry:
                        result_dict = {}
                        for item in entry["ttps"]:
                            result_dict.update(item)
                        all_ttps.append(result_dict)

                ttps_dict["ttps"] = all_ttps
                ttps_dict["sha256"] = f"{sha256_value}"
                if ttps_dict["ttps"]==[]:
                    return {"error": "No ttps found for this hash"}
                else:
                    return ttps_dict

            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}