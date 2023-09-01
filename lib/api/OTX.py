import requests
from OTXv2 import OTXv2, IndicatorTypes
from pandas import json_normalize
import time


class OTX:

    def __init__(self, api_key):

        self.api_key = api_key
        self.base_url = 'https://otx.alienvault.com/api/v1'
        self.headers = {
            "X-OTX-API-KEY": api_key,
        }

    
    def search_sha256(self,hash):


        url = f'{self.base_url}/indicators/file/{hash}'

        try:
            response = requests.get(url, headers=self.headers)
            json_response = response.json()

            if json_response['pulse_info']['count']>0:
                pulse_info = json_response['pulse_info']
                return self.get_pulse_info(pulse_info)
            else:
                print("pulse_info not found in response.")

        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {e}"}



    def get_pulse_info(self,pulse_info):

        pulse_ids = [pulse["id"] for pulse in pulse_info["pulses"]]
        # print(pulse_ids)

        pulse_urls = [f"{self.base_url}/pulses/{pulse_id}" for pulse_id in pulse_ids]
        for url in pulse_urls:
            try:
                response = requests.get(url, headers=self.headers)
                return response.json()

                # json_normalize(indicator_types)
                # time.sleep(5)
                # print("")

                # if json_response['pulse_info']['count']>0:
                #     pulse_info = json_response['pulse_info']
                #     print(f"\npulse_info: {pulse_info} \n\n")
                #     return pulse_info
                # else:
                #     print("pulse_info not found in response.")

            except requests.exceptions.RequestException as e:
                return {"error": f"Request failed: {e}"}



    def get_indicators_types(self):

        indicator_types = [
            IndicatorTypes.IPv4,
            IndicatorTypes.IPv6,
            IndicatorTypes.DOMAIN,
            IndicatorTypes.HOSTNAME,
            IndicatorTypes.EMAIL,
            IndicatorTypes.URL,
            IndicatorTypes.URI,
            IndicatorTypes.FILE_HASH_MD5,
            IndicatorTypes.FILE_HASH_SHA1,
            IndicatorTypes.FILE_HASH_SHA256,
            IndicatorTypes.FILE_HASH_PEHASH,
            IndicatorTypes.FILE_HASH_IMPHASH,
            IndicatorTypes.CIDR,
            IndicatorTypes.FILE_PATH,
            IndicatorTypes.MUTEX,
            IndicatorTypes.CVE,
            IndicatorTypes.YARA
        ]

        # Print name and description of each indicator type
        for indicator_type in indicator_types:
            print("Name:", indicator_type.name)
            print("Description:", indicator_type.description)
            print("-----")
     


# api_key = "d535cee3308ca62de696438152cff365e41b08e62e4f343eeb83e0faaf3beab6"

# otx = OTX(api_key)
# res = otx.search_sha256("0004efbd2df87521c4a440c996b9b13619379453b30534213d3f60f3199e7729")
# print(res)
# otx.get_indicators_types()