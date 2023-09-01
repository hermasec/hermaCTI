import requests
import json
import time


class Intezer:

    def __init__(self, api_key):
        self.Auth_token = ""
        self.api_key = api_key
        self.base_url = 'https://analyze.intezer.com/api/v2-0'
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

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
                time.sleep(6)
                return self.get_ttps(result_url , sha256_value)
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
        

    def get_ttps(self,result_url , sha256_value):
        all_ttps = []

        url = f'{self.base_url}{result_url}/dynamic-ttps'
        self.headers['Authorization'] = 'Bearer ' + self.Auth_token

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            if response.status_code == 200 or 201 or 202:

                data = response.json()

                for entry in data["result"]:
                    if "ttps" in entry:
                        all_ttps.extend(entry["ttps"])    

                ttps_dict = {}
                ttps_dict = {f"ttp_{i}": entry for i, entry in enumerate(all_ttps)}
                ttps_dict["sha256"] = f"{sha256_value}"

                return ttps_dict
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}



        
api_key = "78f86730-b371-4f02-a0dd-846d20c24dc3"


# intezer = Intezer(api_key)
# res = intezer.search_sha256("c42b0d200c2022fba3332dd1078cf1412ba37eb52bd74acf7edb4672b1d0f330")
# print(res)