from stix2_explorer import converter
from stix2_explorer.serialization import JSONEncoder

import json
import urllib3

# TLS certificate validation is disabled.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r4/stix/nist800-53-r4-controls.json"


def main():
    src = converter.get_stix2_data_source(URL)
    for row in src.query():
        print(json.dumps(row, cls=JSONEncoder))


if __name__ == "__main__":
    main()
