from stix2_explorer import converter
from stix2_explorer.serialization import JSONEncoder

import json
import urllib3

# TLS certificate validation is disabled.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URLS = [
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-controls.json",
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-mappings.json",
]


def main():
    src = converter.get_stix2_data_source(URLS)
    for row in src.query():
        print(json.dumps(row, cls=JSONEncoder))


if __name__ == "__main__":
    main()
