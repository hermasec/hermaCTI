import requests

class Virustotal:


    def __init__(self, token):
        self.base_url = "https://www.virustotal.com"
        self.headers = {
            "accept": "application/json",
            "x-apikey": token
        }

    def perform_file_scan(self,file_path):

        url = f'{self.base_url}/api/v3/files'

        files = { "file": (file_path, open(file_path, "rb"), "application/x-msdownload") }

        try:
            response = requests.post(url, files=files, headers=self.headers)
            json_response = response.json()
            print(json_response)

            if 'id' in json_response:
                sha256_value = json_response["data"]["id"]

                print(f"\nSHA256: {sha256_value} \n\n")
                return self.search_sha256(sha256_value)
            else:
                print("SHA256 not found in response.")

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}


    def search_sha256(self, hash):
        path = "/api/v3/analyses/" + hash
        self.response = requests.get(self.base_url + path, headers=self.headers)

    def get_response(self):
        return self.response.json()