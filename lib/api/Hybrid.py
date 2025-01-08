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

    def get_desired_data(self, hash):

        query = {'sha256': {'$eq': hash}}
        data = self.db_manager.find_documents('hybrid', query)

        result_data = {
            "verdict": "",
            "vx_family": "",
            "AVs": {
            }
        }
        if data:
            result_dict = data[0]
            if result_dict.get("scanners_v2")['crowdstrike_ml']:
                crowdstrike_ml_status = result_dict.get("scanners_v2")['crowdstrike_ml']['status']
                result_data["AVs"]["crowdstrike_ml"] = {}
                result_data["AVs"]["crowdstrike_ml"]["status"] = crowdstrike_ml_status
                result_data["AVs"]["crowdstrike_ml"]["result"] = None
                result_data["AVs"]["crowdstrike_ml"]["method"] = None
            else:
                crowdstrike_ml_status = None
            if result_dict.get("scanners_v2")['metadefender']:
                metadefender_status = result_dict.get("scanners_v2")['metadefender']['status']
                result_data["AVs"]["metadefender"] = {}
                result_data["AVs"]["metadefender"]["status"] = metadefender_status
                result_data["AVs"]["metadefender"]["result"] = None
                result_data["AVs"]["metadefender"]["method"] = None
            else:
                metadefender_status = None
            if result_dict.get("scanners_v2")['virustotal']:
                virustotal_status = result_dict.get("scanners_v2")['virustotal']['status']
                result_data["AVs"]["virustotal"] = {}
                result_data["AVs"]["virustotal"]["status"] = virustotal_status
                result_data["AVs"]["virustotal"]["result"] = None
                result_data["AVs"]["virustotal"]["method"] = None
            else:
                virustotal_status = None

            result_data["verdict"] = result_dict.get("verdict")
            result_data["vx_family"] = result_dict.get("vx_family")


        else:
            data = self.search_sha256(hash)

            if "error" in data:
                return data
            else:
                self.db_manager.insert_document('hybrid', data)

                if data.get("scanners_v2")['crowdstrike_ml']:
                    crowdstrike_ml_status = data.get("scanners_v2")['crowdstrike_ml']['status']
                    result_data["AVs"]["crowdstrike_ml"] = {}
                    result_data["AVs"]["crowdstrike_ml"]["status"] = crowdstrike_ml_status
                    result_data["AVs"]["crowdstrike_ml"]["result"] = None
                    result_data["AVs"]["crowdstrike_ml"]["method"] = None

                else:
                    crowdstrike_ml_status = None
                if data.get("scanners_v2")['metadefender']:
                    metadefender_status = data.get("scanners_v2")['metadefender']['status']
                    result_data["AVs"]["metadefender"] = {}
                    result_data["AVs"]["metadefender"]["status"] = metadefender_status
                    result_data["AVs"]["metadefender"]["result"] = None
                    result_data["AVs"]["metadefender"]["method"] = None

                else:
                    metadefender_status = None
                if data.get("scanners_v2")['virustotal']:
                    virustotal_status = data.get("scanners_v2")['virustotal']['status']
                    result_data["AVs"]["virustotal"] = {}
                    result_data["AVs"]["virustotal"]["status"] = virustotal_status
                    result_data["AVs"]["virustotal"]["result"] = None
                    result_data["AVs"]["virustotal"]["method"] = None

                else:
                    virustotal_status = None

                result_data["verdict"] = data.get("verdict")
                result_data["vx_family"] = data.get("vx_family")

        return result_data

    def search_sha256(self, sha256_value):

        url = f'{self.base_url}/overview/{sha256_value}'

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            if response.status_code == 200:
                final_response = response.json()
                if "message" in final_response:
                    message = final_response["message"]
                    return {"error": f"{message}"}
                else:
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
