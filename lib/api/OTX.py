import requests
from OTXv2 import IndicatorTypes
from lib.Database import Database


class OTX:

    def __init__(self, api_key):

        self.api_key = api_key
        self.base_url = 'https://otx.alienvault.com/api/v1'
        self.headers = {
            "X-OTX-API-KEY": api_key,
        }
        self.db_manager = Database(database_name='mydatabase')


    def get_desired_data(self , hash):

        query = {'sha256': {'$eq': hash}}
        data = self.db_manager.find_documents('otx', query)

        result_dict = {}
        for item in data:
            result_dict.update(item)

        if data:
            result_list = []
            for pulse in result_dict["pulses"]:
                attack_name = pulse["name"]
                description = pulse["description"]
                attack_ids = pulse["attack_ids"]
                indicators = pulse["indicators"]

                filtered_indicators=[
                    {"indicator": item["indicator"], "type": item["type"]} for item in indicators
                ]


                dic = {
                        "attack_name" : attack_name,
                        "description" : description,
                        "TTPs" : attack_ids,
                        "IOCs" : filtered_indicators
                }
                result_list.append(dic)

            
        else:
            data = self.search_sha256(hash)
            
            if "error" in data:
                result_list = data
            else:
                inserted_id = self.db_manager.insert_document('otx', data)
                result_list = []
                for pulse in data["pulses"]:
                    attack_name = pulse["name"]
                    description = pulse["description"]
                    attack_ids = pulse["attack_ids"]

                    indicators = pulse["indicators"]

                    filtered_indicators = [
                        {"indicator": item["indicator"], "type": item["type"]} for item in indicators
                    ]

                    dic = {
                        "attack_name": attack_name,
                        "description": description,
                        "TTPs": attack_ids,
                        "IOCs": filtered_indicators
                    }
                    result_list.append(dic)

                
        return result_list
    


        
    def search_sha256(self,hash):


        url = f'{self.base_url}/indicators/file/{hash}'

        try:
            response = requests.get(url, headers=self.headers)
            json_response = response.json()


            if json_response['pulse_info']['count']>0:
                pulse_info = json_response['pulse_info']
                return self.get_pulse_info(pulse_info , hash)
            else:
                return {"error": "attack_info not found in response"}

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}



    def get_pulse_info(self,pulse_info , hash):

        pulse_ids = [pulse["id"] for pulse in pulse_info["pulses"]]
        result_list = []

        pulse_urls = [f"{self.base_url}/pulses/{pulse_id}" for pulse_id in pulse_ids]
        for url in pulse_urls:
            try:
                response = requests.get(url, headers=self.headers)
                result_list.append(response.json())

                result_dict = {}
                result_dict["pulses"] = result_list
                result_dict["sha256"] = f"{hash}"

            except requests.exceptions.RequestException as e:
                return {"error": f"Request failed: {e}"}
        return result_dict