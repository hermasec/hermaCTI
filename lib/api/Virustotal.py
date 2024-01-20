import requests
from lib.Database import Database


class Virustotal:

    def __init__(self, api_key):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        self.db_manager = Database(database_name='mydatabase')

    def get_desired_data(self, hash):

        query = {'data.id': {'$eq': hash}}
        data = self.db_manager.find_documents('virustotal', query)
        result_data = {
            "status": "",
            "family": "",
            "AVs": {}
        }

        if data:
            AVs = self.AV_results(data[0])
            result_data["AVs"] = AVs
            if "popular_threat_classification" in data[0]["data"]["attributes"]:
                result_data["family"] = data[0]["data"]["attributes"]["popular_threat_classification"][
                    "suggested_threat_label"]
            result_data["status"] = self.detect_status(data[0])


            return result_data

        else:
            data = self.search_sha256(hash)

            if "error" in data:
                return {}
            else:
                self.db_manager.insert_document('virustotal', data)

                AVs = self.AV_results(data)
                result_data["AVs"] = AVs
                if "popular_threat_classification" in data["data"]["attributes"]:
                    result_data["family"] = data["data"]["attributes"]["popular_threat_classification"]["suggested_threat_label"]
                result_data["status"] = self.detect_status(data)

                return result_data

    def search_sha256(self, hash):
        url = f'{self.base_url}/files/{hash}'

        try:
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}

    def AV_results(self, data):

        engines = {}

        for engine, info in data['data']['attributes']['last_analysis_results'].items():
            engines[engine] = {
                "status": info['category'],
                "result": info['result'],
                "method": info['method']
            }

        return engines

    def detect_status(self,data):
        malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
        undetected = data["data"]["attributes"]["last_analysis_stats"]["undetected"]
        clean = data["data"]["attributes"]["last_analysis_stats"]["harmless"]

        file_status = ""
        if malicious>undetected and malicious>clean:
            file_status = "malicious"
        elif undetected>malicious or clean>malicious:
            file_status = "clean"
        else:
            file_status = "no-result"
        return file_status



    def search_ttps(self, hash):
        url = f'{self.base_url}/files/{hash}/behaviour_mitre_trees'
        try:
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}

    def get_ttps(self, hash):

        query = {'data.id': {'$eq': hash}}
        data = self.db_manager.find_documents('virustotal', query)

        if data:
            if 'mitre' in data[0]:
                return data[0]["mitre"]
            else:
                ttps = self.search_ttps(hash)

                if "error" in ttps:
                    return_data = {}
                elif ttps["data"] == {}:
                    return_data = {}
                else:
                    filter = {'data.id': hash}
                    newvalues = {"$set": {'mitre': ttps}}
                    self.db_manager.update_document('virustotal', filter, newvalues)
                    return_data = ttps

                return return_data
        else:
            return {"error": "no virustotal data available for this hash"}
