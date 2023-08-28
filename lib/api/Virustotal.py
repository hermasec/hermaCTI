import requests


class Virustotal:

    def __init__(self):
        self.response = None

    def __int__(self, token):
        self.url = "https://www.virustotal.com"
        self.headers = {
            "accept": "application/json",
            "x-apikey": "199b22b0da5bc1ffcf0700b043b07c0f578cef4a74593f1447e53bb9667543ce"
        }

    def search_sha256(self, hash):
        path = "/api/v3/files/" + hash
        self.response = requests.get(self.url + path, headers=self.headers)

    def get_response(self):
        return self.response.json()