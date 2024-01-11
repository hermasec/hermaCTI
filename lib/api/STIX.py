from stix2 import Filter, TAXIICollectionSource
from taxii2client.v20 import Collection
from taxii2client import Server
from stix2.v21 import (Indicator, Malware, Relationship, Bundle, AttackPattern)
from lib.Database import Database
from datetime import datetime

collections = {
    "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
    "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b",
    "ics-attack": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
}

# collection = Collection(f"https://cti-taxii.mitre.org/stix/collections/{collections['enterprise_attack']}/")
# src = TAXIICollectionSource(collection)
#
# t1134 = src.query([
#     Filter("external_references.external_id", "=", "T1134"),
#     Filter("type", "=", "attack-pattern")
# ])[0]
#
# print(t1134)

# XX = src.query([
# Filter("type", "=", "relationship"),
# Filter("relationship_type", "=", "uses"),
# Filter("target_ref", "=", "malware--08e844a8-371f-4fe3-9d1f-e056e64a7fde")
# ])
#
# print(XX)


# XX = src.query([
#     Filter("type", "=", "indicator"),
#     Filter("pattern", "=", "[file:hashes.'SHA-256' = 'cc60a0c480e4d898fa77ab501bbd2afaf3f5fb89a2917a31e7f5fdaa6c3879c']")
#
# ])


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
        elif "domain" in type or "hostname" in value:
            indicator_pattern = f"[domain-name: value = '{value}']"
        elif "IPv4" in type:
            indicator_pattern = f"[ipv4-addr: value = '{value}']"
        elif "url" in type:
            indicator_pattern = f"[url: value = '{value}']"
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

        for attack in json_data["Attacks"]:
            for ioc in attack["IOCs"]:
                stix_indicator = self.create_indicator(ioc["type"], ioc["indicator"])
                stix_indicators.append(stix_indicator)

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

        if json_data["file_status"] == "malicious":
            malware_family = json_data["family"]
            malware_name = json_data["fileinfo"]["name"]
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
        md5 = json_data["fileinfo"]["md5"]
        sha256 = json_data["sha256"]

        for indicator in indicators:
            relationships = []
            if sha256 in indicator["pattern"]:
                sha256_relationship = Relationship(indicator, 'indicates', malware)
                relationships.append(sha256_relationship)

            if md5 in indicator["pattern"]:
                md5_relationship = Relationship(indicator, 'indicates', malware)
                relationships.append(md5_relationship)

        for attack_pattern in attack_patterns:
            attack_pattern_relationship = Relationship(attack_pattern, 'uses', malware)
            relationships.append(attack_pattern_relationship)

        return relationships

    def all_stix_data(self, json_data):
        IOCs = self.ioc2stix(json_data)
        malware = self.malicousfile2stix(json_data)
        TTPs = self.ttp2stix(json_data)
        relationships = self.create_relationships(json_data, IOCs, malware, TTPs)

        bundle = Bundle(objects= [malware] + IOCs + TTPs + relationships)

        return bundle


# st = STIX()
# print(st.all_stix_data(json_data))


# # Your CTI data
# filter = Filter()
# cti_data = filter.get_hash_data("1e931660cce69add24e405c9fbdd3072190c9f716c1675334f00d0bdbf84bf46")
#
#
# # Create STIX bundle
# stix_bundle = convert_to_stix(cti_data)
#
# # Serialize STIX bundle to JSON
# stix_json = stix_bundle.serialize(pretty=True)
#
# # Save STIX data to a file or send it to a TAXII server
# with open("stix_data.json", "w") as f:
#     f.write(stix_json)

# # TAXII Server Setup
# server = Server("https://your-taxii-server.com/taxii/")
# collection = Collection("Your Collection ID", server)
#
# # Publish STIX data to TAXII server
# collection.add_objects(stix_bundle)
#
# # Query STIX data from TAXII server
# query = "type:indicator"
# result = collection.get_objects(query)
#
# for indicator in result:
#     print(indicator)
