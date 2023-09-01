import requests
from lib.Database import Database


class Virustotal:

    def __init__(self, token):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": token
        }
        self.db_manager = Database(database_name='mydatabase')


    def perform_file_scan(self,file_path):

        url = f'{self.base_url}/api/v3/files'

        files = { "file": (file_path, open(file_path, "rb"), "application/x-msdownload") }

        try:
            response = requests.post(url, files=files, headers=self.headers)
            json_response = response.json()

            if 'id' in json_response:
                analyze_url = json_response["data"]["links"]["self"]
                json_response = requests.get(analyze_url, headers=self.headers)
                if 'sha256' in response:
                    file_sha256 = json_response["sha256"]
                    return self.search_sha256(file_sha256)
                else:
                    {"error": "sha256 not found in response"}
            else:
                {"error": "analyse id not found in response"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}


    def get_desired_data(self , hash):

        query = {'data.id': {'$eq': hash}}
        data = self.db_manager.find_documents('virustotal', query)

        if data:
            result_dict = {}
            for item in data:
                result_dict.update(item)

            data = {    "malicious" : self.malicious(result_dict),
                        "undetected" : self.undetected(result_dict)

                     }

        else:
            data = self.search_sha256(hash)
            
            if "error" in data:
                pass
            else:
                inserted_id = self.db_manager.insert_document('virustotal', data)

                data = {   "malicious" : self.malicious(data),
                            "undetected" : self.undetected(data)

                                }
        return data





    def search_sha256(self, hash):
        url = f'{self.base_url}/files/{hash}'

        # f = open('uploads\\res.json')
        # data = json.load(f)
        # return data


        try:
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                print(response)
                
                return response.json()
            else:
                return {"error": f"Request failed with status code: {response.status_code}"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}

        
    
    def malicious(self , data):

        malicious_engines = {}

        # Extract engine names with category "malicious" and store in the dictionary
        for engine, info in data['data']['attributes']['last_analysis_results'].items():
            if info['category'] == 'malicious':
                malicious_engines[engine] = {
                    "result": info['result'],
                    "method": info['method']
                }

        return malicious_engines
    

    def undetected(self , data):

        undetected_engines = {}

        for engine, info in data['data']['attributes']['last_analysis_results'].items():
            if info['category'] == 'undetected':
                undetected_engines[engine] = {
                    "result": info['result'],
                    "method": info['method']
                }

        return undetected_engines




        
    

# token="199b22b0da5bc1ffcf0700b043b07c0f578cef4a74593f1447e53bb9667543ce"
# vir = Virustotal(token)
# # 1a1c5cfc2a24ba5eaa67035d1ca2b5d954597de7dda0154eaef8f66d537672b0
# res = vir.get_desired_data()
# print(type(res))