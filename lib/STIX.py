from stix2.v21 import (Indicator, Malware, Relationship, Bundle, AttackPattern)
from lib.Database import Database
from datetime import datetime

class STIX:
    def __init__(self):
        self.db_manager = Database(database_name='mydatabase')

    def create_indicator(self, type, value):

        if "FileHash" in type:
            if "SHA256" in type:
                indicator_pattern = f"[file:hashes.'SHA-256'='{value}']"
            elif "MD5" in type:
                indicator_pattern = f"[file:hashes.'MD5'='{value}']"
            elif "SHA1" in type:
                indicator_pattern = f"[file:hashes.'SHA1'='{value}']"
        elif "domain" in type or "hostname" in type:
            indicator_pattern = f"[domain-name: value = '{value}']"
        elif "IPv4" in type:
            indicator_pattern = f"[ipv4-addr: value = '{value}']"
        elif "URL" in type:
            new_value = value.replace('"', '').replace("'", '')
            new_value = new_value.replace('\\', '/')
            indicator_pattern = f"[url: value = '{new_value}']"
        else:
            indicator_pattern = f"[cve: value = '{value}']"

        indicator = Indicator(
            indicator_types=["malicious-activity"],
            pattern=indicator_pattern,
            pattern_type="stix",
            pattern_version="2.1"
        )

        return indicator

    def ioc2stix(self, json_data):
        stix_indicators = []

        if json_data["Attacks"]:
            for attack in json_data["Attacks"]:
                for ioc in attack["IOCs"]:
                    stix_indicator = self.create_indicator(ioc["type"], ioc["indicator"])
                    stix_indicators.append(stix_indicator)
        else:
            indicator_sha256 = self.create_indicator("FileHash-SHA256", json_data["sha256"])
            stix_indicators.append(indicator_sha256)
            indicator_md5 = self.create_indicator("FileHash-MD5", json_data["fileinfo"]["md5"])
            stix_indicators.append(indicator_md5)

        return stix_indicators

    def ttp2stix(self, json_data):
        stix_attack_patterns = []
        mitre_data = json_data["TTPs"]["data"]

        for framework, tactics in mitre_data.items():
            for tactic in tactics["tactics"]:
                for technique in tactic["techniques"]:
                    kill_chain_phases = []
                    kill_chain_phases.append({"kill_chain_name": "mitre-attack", "phase_name": tactic["name"]})

                    attack_pattern = AttackPattern(
                        name=technique["name"],
                        description=technique["description"],
                        external_references=[
                            {"source_name": "mitre-attack", "url": technique["link"], "external_id": technique["id"]}],
                        kill_chain_phases=kill_chain_phases
                    )

                    stix_attack_patterns.append(attack_pattern)

        return stix_attack_patterns

    def malicousfile2stix(self, json_data):

        malware_family = json_data["family"]

        malware_name = json_data["fileinfo"]["name"] if json_data["fileinfo"]["name"] is not None else ""
        created = self.transfertime(json_data["fileinfo"]["time"]["created"]) if json_data["fileinfo"]["time"][
                                                                                     "created"] is not None else None
        modified = self.transfertime(json_data["fileinfo"]["time"]["modified"]) if json_data["fileinfo"]["time"][
                                                                                       "modified"] is not None else None

        malware = Malware(
            name=malware_name,
            malware_types=[malware_family],
            created=created,
            modified=modified,
            is_family="true"
        )

        return malware

    def transfertime(self, datetime_string):
        dt = datetime.strptime(datetime_string, "%a %b %d %H:%M:%S %Y")
        timestamp_string = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        return timestamp_string

    def create_relationships(self, json_data, indicators, malware, attack_patterns):
        relationships = []
        md5 = json_data["fileinfo"]["md5"]
        sha256 = json_data["sha256"]

        for indicator in indicators:
            if sha256 in indicator["pattern"]:
                sha256_relationship = Relationship(indicator, 'indicates', malware)
                relationships.append(sha256_relationship)

            if md5 in indicator["pattern"]:
                md5_relationship = Relationship(indicator, 'indicates', malware)
                relationships.append(md5_relationship)

        if attack_patterns:
            for attack_pattern in attack_patterns:
                attack_pattern_relationship = Relationship(attack_pattern, 'uses', malware)
                relationships.append(attack_pattern_relationship)

        return relationships

    def all_stix_data(self, json_data):
        IOCs = self.ioc2stix(json_data)
        malware = self.malicousfile2stix(json_data)
        if "data" in json_data["TTPs"]:
            TTPs = self.ttp2stix(json_data)
        else:
            TTPs = None

        relationships = self.create_relationships(json_data, IOCs, malware, TTPs)

        if TTPs:
            bundle = Bundle(objects= [malware] + IOCs + TTPs + relationships)
        else:
            bundle = Bundle(objects=[malware] + IOCs + relationships)

        return bundle