import os
import re
from datetime import datetime
import yara
from lib.Database import Database


class Yara:

    def __init__(self):
        self.db_manager = Database(database_name='mydatabase')
        self.all_rules_source = ""

    def compile_rules(self):
        compiled_rules_path = "compiled_rules"
        directory_path = '.\\rules-master'

        all_rules_source = ""

        # Iterate over each YARA rule file in the directory
        for filename in os.listdir(directory_path):
            if filename.endswith('.yar'):
                rule_file_path = os.path.join(directory_path, filename)

                # Read the YARA rules from the file
                with open(rule_file_path, 'r') as rule_file:
                    yara_rules = rule_file.read()

                # Concatenate the YARA rules source strings
                all_rules_source += "\n" + yara_rules

        self.all_rules_source = all_rules_source

        if os.path.exists(compiled_rules_path):
            rules = yara.load(compiled_rules_path)
        else:
            compiled_rules = yara.compile(source=all_rules_source)
            compiled_rules.save(compiled_rules_path)
            rules = yara.load(compiled_rules_path)

        return rules

    def extract_rule_by_name(self, all_rules_source, rule_name):
        # Construct a regular expression pattern to match the given rule_name
        pattern = r'rule\s+' + re.escape(rule_name) + r'[^{]*\{(.*?)^}'

        # Use re.DOTALL to make '.' match newline characters
        match = re.search(pattern, all_rules_source, re.DOTALL | re.MULTILINE)

        if match:
            extracted_rule = match.group(0)
            return extracted_rule.strip()
        else:
            return None

    def get_matched_rules_sources(self, target_file_path):
        try:
            rules = self.compile_rules()
            matches = rules.match(target_file_path)

            if matches:
                matched_rules = []
                for rule in matches:
                    matched_rules.append(rule.rule)

                matched_rules_source = ""
                for rulename in matched_rules:
                    result = self.extract_rule_by_name(self.all_rules_source, rulename)
                    matched_rules_source += "\n" + result
                return matched_rules_source
            else:
                return {"No matches found."}
        except yara.Error as e:
            return ""

    def yara_scanner(self, target_file_path):
        example_yara_rule_file = ".\\rules\\scanners_yara_rules.yar"

        if os.path.exists(example_yara_rule_file):
            return example_yara_rule_file
        else:
            matched_rules_source = self.get_matched_rules_sources(target_file_path)
            with open(example_yara_rule_file, 'w') as yar_file:
                yar_file.write(matched_rules_source)
                return example_yara_rule_file


    def yara_generator(self, file_size, sha256):

        date = datetime.now().strftime("%Y-%m-%d")
        yara_rule_template = """import "hash"
rule filesize_and_hash {{

    meta:
        author = "hermaCTI"
        date = "{date}"
        description = "This yara rule finds a file with sh256 hash of {sha256_hash}"
        sha256_hash = "{sha256_hash}"
    condition:
        filesize == {size} and
        hash.sha256(0, filesize) == "{sha256_hash}"
}}
        """

        yara_rule = yara_rule_template.format(size=file_size, sha256_hash=sha256, date=date)
        example_yara_rule_file = ".\\rules\\generated_yara_rule.yar"
        if os.path.exists(example_yara_rule_file):
            return example_yara_rule_file
        else:
            with open(example_yara_rule_file, 'w') as yar_file:
                yar_file.write(yara_rule)
                return example_yara_rule_file

