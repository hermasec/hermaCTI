import requests


class Hybrid:

    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://www.hybrid-analysis.com/api/v2'
        self.headers = {
            'accept': 'application/json',
            'user-agent': 'Falcon Sandbox',
            'api-key': api_key,
        }

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
                print("SHA256 not found in response.")

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}
        

    def search_sha256(self,sha256_value):

        url = f'{self.base_url}/overview/{sha256_value}'

        try:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}