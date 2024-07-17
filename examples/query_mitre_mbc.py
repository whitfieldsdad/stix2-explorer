from stix2_explorer import converter
from stix2_explorer.serialization import JSONEncoder

import json
import urllib3

# TLS certificate validation is disabled.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://raw.githubusercontent.com/MBCProject/mbc-stix2.1/master/mbc/mbc.json"


def main():
    src = converter.get_stix2_data_source(URL)
    for row in src.query():
        print(json.dumps(row, cls=JSONEncoder))


if __name__ == "__main__":
    main()
