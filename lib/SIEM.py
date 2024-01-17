import os
import re
from datetime import datetime
import yaml
from lib.Database import Database


class SIEM:

    def __init__(self):
        self.db_manager = Database(database_name='mydatabase')

    def generate_sigma_yaml(self, cti_data):

        sha256 = cti_data["sha256"]

        ioc_list = []
        for attack in cti_data["Attacks"]:
            for ioc in attack["IOCs"]:
                indicator_value = ioc.get('indicator')
                ioc_list.append(indicator_value)

        if ioc_list:
            date = datetime.now().strftime("%Y-%m-%d")
            rule_template = {
                "title": "Detect IOCs",
                "id": f"detect_ioc_{sha256}",
                "status": "experimental",
                "description": f"Detects the presence of IOCs in logs related to file with sha256: {sha256}",
                "author": "hermaCTI",
                "date": date,
                "logsource": {
                    "category": "your_log_category",
                    "product": "your_log_product",
                    "service": "your_log_service"
                },
                "detection": {
                    "keywords": ioc_list,
                    "condition" : "keywords",
                    "falsepositives": "Possible false positives",
                    "tags": ["IOC detection"]
                }
            }

            yaml_data = yaml.dump(rule_template, default_flow_style=False)
            modified_yaml_data = self.enclose_in_single_quotes(yaml_data)

            return modified_yaml_data
        else:
            return []


    def enclose_in_single_quotes(self,input_string):
        # Define the regex pattern
        pattern = r'- (.*)'

        # Use re.sub to replace matches with the enclosed version
        result_string = re.sub(pattern, r"- '\1'", input_string)

        return result_string

    def get_sigma_rule(self, cti_data):

        sha256 = cti_data["sha256"]

        query = {'sha256': {'$eq': sha256}}
        data = self.db_manager.find_documents('rules', query)


        example_sigma_rule_file = ".\\rules\\sigma_rule.yaml"

        if os.path.exists(example_sigma_rule_file):
            return example_sigma_rule_file
        else:
            yaml_data = self.generate_sigma_yaml(cti_data)
            if yaml_data:
                with open(example_sigma_rule_file, 'w') as yaml_file:
                    yaml_file.write(yaml_data)
                    return example_sigma_rule_file
            else:
                return None
