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

        if data:
            result_dict = {}
            for item in data:
                result_dict.update(item)

            AVs = self.AV_results(result_dict)
            return AVs

        else:
            data = self.search_sha256(hash)

            if "error" in data:
                pass
            else:
                inserted_id = self.db_manager.insert_document('virustotal', data)

                AVs = self.AV_results(data)
                return AVs

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

    def malicious(self, data):

        malicious_engines = {}

        # Extract engine names with category "malicious" and store in the dictionary
        for engine, info in data['data']['attributes']['last_analysis_results'].items():
            if info['category'] == 'malicious':
                malicious_engines[engine] = 'malicious'

        return malicious_engines

    def undetected(self, data):

        undetected_engines = {}

        for engine, info in data['data']['attributes']['last_analysis_results'].items():
            if info['category'] == 'undetected':
                undetected_engines[engine] = 'undetected'

        return undetected_engines

    def AV_results(self, data):

        engines = {}

        for engine, info in data['data']['attributes']['last_analysis_results'].items():
            engines[engine] = {
                "status": info['category'],
                "result": info['result'],
                "method": info['method']
            }

        return engines
