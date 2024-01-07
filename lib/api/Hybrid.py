import requests
from lib.Database import Database


class Hybrid:

    def __init__(self, api_key):
        self.base_url = 'https://www.hybrid-analysis.com/api/v2'
        self.headers = {
            'accept': 'application/json',
            'user-agent': 'Falcon Sandbox',
            'api-key': api_key,
        }
        self.db_manager = Database(database_name='mydatabase')

    def perform_quick_scan(self,file_path):


        url = f'{self.base_url}/quick-scan/file'

        data = {
            'scan_type': 'all',
            'no_share_third_party': '',
            'allow_community_access': '',
            'comment': '',
            'submit_name': ''
        }
        files = {
            'file': (file_path, open(file_path, 'rb'))
        }

        try:
            response = requests.post(url, headers=self.headers, data=data, files=files)
            json_response = response.json()

            if 'sha256' in json_response:
                sha256_value = json_response['sha256']
                print(f"\nSHA256: {sha256_value} \n\n")
                return self.search_sha256(sha256_value)
            else:
                {"error": "SHA256 not found in response"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
        


    def get_desired_data(self , hash):

        query = {'sha256': {'$eq': hash}}
        data = self.db_manager.find_documents('hybrid', query)

        

        if data:
            result_dict = {}
            for item in data:
                result_dict.update(item)

            crowdstrike_ml_status = result_dict.get("scanners_v2")['crowdstrike_ml']['status']
            metadefender_status = result_dict.get("scanners_v2")['metadefender']['status']
            virustotal_status = result_dict.get("scanners_v2")['virustotal']['status']

            data = {
                "verdict": result_dict.get("verdict"),
                "vx_family": result_dict.get("vx_family"),
                "AVs" :{
                    "crowdstrike_ml": {
                        "status": crowdstrike_ml_status,
                        "result": None,
                        "method": None
                    },
                    "metadefender": {
                        "status": metadefender_status,
                        "result": None,
                        "method": None
                    },
                    "virustotal": {
                        "status": virustotal_status,
                        "result": None,
                        "method": None
                    }
                }
            }


        else:
            data = self.search_sha256(hash)

            if "error" in data:
                return data
            else:

                inserted_id = self.db_manager.insert_document('hybrid', data)

                crowdstrike_ml_status = data.get("scanners_v2")['crowdstrike_ml']['status']
                metadefender_status = data.get("scanners_v2")['metadefender']['status']
                virustotal_status = data.get("scanners_v2")['virustotal']['status']

                data = {
                    "verdict": data.get("verdict"),
                    "vx_family": data.get("vx_family"),
                    "AVs": {
                        "crowdstrike_ml": {
                            "status": crowdstrike_ml_status,
                            "result":None,
                            "method":None
                        },
                        "metadefender": {
                            "status": metadefender_status,
                            "result": None,
                            "method": None
                        },
                        "virustotal": {
                            "status": virustotal_status,
                            "result": None,
                            "method": None
                        }
                    }
                }

        return data
        

    def search_sha256(self,sha256_value):

        url = f'{self.base_url}/overview/{sha256_value}'

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            if response.status_code == 200:
                final_response=response.json()
                null_count = 0
                for scanner in final_response['scanners']:
                    percent_value = scanner.get('percent')
                    if percent_value is None:
                        null_count += 1

                if null_count > 2:
                    self.search_sha256(sha256_value)
                else:
                    return final_response
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
