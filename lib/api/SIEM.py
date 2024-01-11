class SIEM:
    def generate_splunk_rule(self,cti_data):
        # Extract relevant information from CTI data
        ioc_indicators = []
        for attack in cti_data["Attacks"]:
            for ioc in attack["IOCs"]:
                ioc_indicators.append(ioc)

        ttp_list = cti_data.get('TTPs', [])
        file_hash_sha256 = cti_data.get('sha256', "")

        # Build Splunk search query
        splunk_query = f"index=your_index sourcetype=your_sourcetype "

        # Add IOC indicators to the search query
        for ioc in ioc_indicators:
            indicator_type = ioc.get('type', '')
            indicator_value = ioc.get('indicator', '')
            splunk_query += f"OR search {indicator_type}={indicator_value} "

        # Add SHA256 file hash to the search query
        if file_hash_sha256:
            splunk_query += f"OR search sha256={file_hash_sha256} "

        # Add TTPs to the search query
        for ttp in ttp_list:
            splunk_query += f"OR search {ttp} "

        # Finalize the query
        splunk_query += "| stats count by source_ip | where count > 0 | table source_ip, count"

        return splunk_query


cti_data = {
    "Attacks": [
        {
            "IOCs": [
                {
                    "indicator": "statad.de",
                    "type": "domain"
                },
                {
                    "indicator": "adstat.red",
                    "type": "domain"
                },
                {
                    "indicator": "c5119b8a75d4965e51e7424964bf92f2708b099a4e6049b13f8aaddabfb6860e",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "9f64fec50d4447175459aab33bc9126f9a3370d8",
                    "type": "FileHash-SHA1"
                },
                {
                    "indicator": "292180b80737f2507a5949a4f7e7a6c8",
                    "type": "FileHash-MD5"
                },
                {
                    "indicator": "f03f4617b3be8dd99ed959f2119c24d9",
                    "type": "FileHash-MD5"
                },
                {
                    "indicator": "ff293f939baa2f787a4fde258a97d165cb9a086cda83b92f9d52c5125957d2b5",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "c8c4b6bcb4b583ba69663ec3aed8e1e01f310f9f",
                    "type": "FileHash-SHA1"
                }
            ],
            "TTPs": [
                "T1108",
                "T1112",
                "T1143",
                "T1196",
                "T1202",
                "T1203",
                "T1204",
                "T1210",
                "T1480",
                "T1497",
                "T1518"
            ],
            "attack_name": "InvisiMole: The hidden part of the story",
            "description": "In late 2019, the InvisiMole Group resurfaced with an updated toolset, targeting a few high-profile\norganizations in the military sector and diplomatic missions, both in Eastern Europe. \n\nESET researchers conducted an investigation of these attacks in cooperation with the affected organizations and were able to uncover the extensive, sophisticated toolset used for delivery, lateral movement and execution of InvisiMole's backdoors-the missing pieces of the puzzle in our previous research."
        },
        {
            "IOCs": [
                {
                    "indicator": "fa2edd8a24266f9ecccea44b4b47100f",
                    "type": "FileHash-MD5"
                },
                {
                    "indicator": "27fc1dcb1b3dca3e496f799a2944e4fb070af39c",
                    "type": "FileHash-SHA1"
                },
                {
                    "indicator": "c5119b8a75d4965e51e7424964bf92f2708b099a4e6049b13f8aaddabfb6860e",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "0a663f781913a8ca81359ba77b00086f",
                    "type": "FileHash-MD5"
                },
                {
                    "indicator": "f8caa729c28ef6b0ec8aa74399ce4ee7a59b895c",
                    "type": "FileHash-SHA1"
                },
                {
                    "indicator": "ffb74af734453973fed6663c16fb001d563faf1c",
                    "type": "FileHash-SHA1"
                },
                {
                    "indicator": "a16b3f8aa869aebb61ae770f9701d918c4a814a4502f46a93e904d38084d23b2",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "be554e706f6b8ab8f4bbea209b669e9dca98bf647faa55c46756f322dadab32f",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "95.215.111.109",
                    "type": "IPv4"
                },
                {
                    "indicator": "adstat.red",
                    "type": "domain"
                },
                {
                    "indicator": "wlsts.net",
                    "type": "domain"
                },
                {
                    "indicator": "blabla234342.sytes.net",
                    "type": "hostname"
                },
                {
                    "indicator": "updatecloud.sytes.net",
                    "type": "hostname"
                },
                {
                    "indicator": "updchecking.sytes.net",
                    "type": "hostname"
                }
            ],
            "TTPs": [],
            "attack_name": "namer",
            "description": ""
        },
        {
            "IOCs": [
                {
                    "indicator": "fa2edd8a24266f9ecccea44b4b47100f",
                    "type": "FileHash-MD5"
                },
                {
                    "indicator": "27fc1dcb1b3dca3e496f799a2944e4fb070af39c",
                    "type": "FileHash-SHA1"
                },
                {
                    "indicator": "c5119b8a75d4965e51e7424964bf92f2708b099a4e6049b13f8aaddabfb6860e",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "f8caa729c28ef6b0ec8aa74399ce4ee7a59b895c",
                    "type": "FileHash-SHA1"
                },
                {
                    "indicator": "fb4401dea8911beab788e87a576ef5568da82ed5",
                    "type": "FileHash-SHA1"
                },
                {
                    "indicator": "a16b3f8aa869aebb61ae770f9701d918c4a814a4502f46a93e904d38084d23b2",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "be554e706f6b8ab8f4bbea209b669e9dca98bf647faa55c46756f322dadab32f",
                    "type": "FileHash-SHA256"
                },
                {
                    "indicator": "46.165.230.241",
                    "type": "IPv4"
                },
                {
                    "indicator": "updchecking.sytes.net",
                    "type": "hostname"
                }
            ],
            "TTPs": [],
            "attack_name": "tange",
            "description": "The full text of the report on InvisiMole, which was published by WeLive security, has been published on the BBC's News Channel and is available to view on iPlayer."
        }
    ],
    "TTPs": [
        "T1218.011",
        "T1055",
        "T1055.003",
        "T1112",
        "T1614.001",
        "T1057",
        "T1070.004",
        "T1027",
        "T1056.001",
        "T1135",
        "T1070.006",
        "T1036",
        "T1016.001",
        "T1059"
    ],
    "family": "Trojan.Generic",
    "file_status": "malicious",
    "fileinfo": {
        "file_extension": "exe",
        "md5": "fa2edd8a24266f9ecccea44b4b47100f",
        "name": "AlcRmv",
        "scan_date": "Sat, 06 Jan 2024 01:07:50 GMT",
        "sha256": "c5119b8a75d4965e51e7424964bf92f2708b099a4e6049b13f8aaddabfb6860e",
        "size": "190.5 kB",
        "time": {
            "compilation": "Fri Sep 06 16:33:56 2019",
            "created": "Fri Sep 06 16:33:56 2019",
            "modified": "Sun Dec 31 13:17:29 2023"
        },
        "type": "PE32+ executable (GUI) x86-64, for MS Windows"
    },
    "has_IOC": True,
    "has_TTP": True,
    "sha256": "c5119b8a75d4965e51e7424964bf92f2708b099a4e6049b13f8aaddabfb6860e"
}

siem = SIEM()
print(siem.generate_splunk_rule(cti_data))