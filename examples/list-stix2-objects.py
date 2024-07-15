import json
from typing import Optional
from stix2_explorer import util
from stix2_explorer.util import JSONEncoder
from examples.constants import *

import logging
import urllib3

# We ignore TLS certificate verification to improve stability.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


def main(
        object_ids: Optional[str],
        object_types: Optional[str],
        include_all: bool,
        include_attack: bool, 
        include_capec: bool, 
        include_mbc: bool, 
        include_nist_sp_800_53: bool, 
        include_attack_to_nist_sp_800_53: bool, 
        include_revoked: bool,
        include_deprecated: bool):
    
    src = get_stix2_data_source(
        include_all=include_all,
        include_attack=include_attack, 
        include_capec=include_capec, 
        include_mbc=include_mbc, 
        include_nist_sp_800_53=include_nist_sp_800_53, 
        include_attack_to_nist_sp_800_53=include_attack_to_nist_sp_800_53,
    )
    rows = src.query()

    if not (include_revoked or include_deprecated):
        rows = util.filter_stix2_objects(
            rows,
            object_ids=object_ids,
            object_types=object_types,
            include_revoked=include_revoked,
            include_deprecated=include_deprecated
        )

    for o in rows:
        print(json.dumps(o, cls=JSONEncoder))


def get_stix2_data_source(
        include_all: bool,
        include_attack: bool, 
        include_capec: bool, 
        include_mbc: bool, 
        include_nist_sp_800_53: bool, 
        include_attack_to_nist_sp_800_53: bool):
    
    srcs = []

    if include_all:
        include_attack = True
        include_capec = True
        include_mbc = True
        include_nist_sp_800_53 = True
        include_attack_to_nist_sp_800_53 = True

    if include_attack:
        logger.info("Loading ATT&CK...")
        srcs.append(util.get_data_source_with_fallback(ATTACK_ENTERPRISE_PATH, ATTACK_ENTERPRISE_URL))

    if include_capec:
        logger.info("Loading CAPEC...")
        srcs.append(util.get_data_source_with_fallback(CAPEC_PATH, CAPEC_URL))

    if include_mbc:
        logger.info("Loading Malware Behavior Catalog...")
        srcs.append(util.get_data_source_with_fallback(MITRE_MBC_PATH, MITRE_MBC_URL))

    if include_nist_sp_800_53:
        logger.info("Loading NIST SP 800-53...")
        srcs.append(util.get_data_source_with_fallback(NIST_SP_800_53_PATH, NIST_SP_800_53_URL))
    
    if include_attack_to_nist_sp_800_53:
        logger.info("Loading ATT&CK to NIST SP 800-53...")
        srcs.append(util.get_data_source_with_fallback(MITRE_ATTACK_TO_NIST_SP_800_53_PATH, MITRE_ATTACK_TO_NIST_SP_800_53_URL))

    if not srcs:
        raise ValueError("No data sources specified.")
    return util.get_data_source(srcs)


if __name__ == "__main__":
    def cli():
        import argparse

        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

        parser = argparse.ArgumentParser(description="Query STIX 2 objects")
        parser.add_argument("--include-all", action="store_true")        
        parser.add_argument("--include-attack", action="store_true")
        parser.add_argument("--include-capec", action="store_true")
        parser.add_argument("--include-mbc", action="store_true")
        parser.add_argument("--include-nist-sp-800-53", action="store_true")
        parser.add_argument("--include-attack-to-nist-sp-800-53", action="store_true")
        parser.add_argument("--include-revoked", action="store_true")
        parser.add_argument("--include-deprecated", action="store_true")
        parser.add_argument('--object-id', "-i", nargs='+')
        parser.add_argument("--object-type", "-t", nargs='+')
        args = parser.parse_args()

        kwargs = vars(args)
        kwargs.update({
            'object_ids': kwargs.pop('object_id', None),
            'object_types': kwargs.pop('object_type', None),
        })
        
        include_all = kwargs.get('include_all')
        if include_all:
            kwargs.update({
                'include_attack': True,
                'include_capec': True,
                'include_mbc': True,
                'include_nist_sp_800_53': True,
                'include_attack_to_nist_sp_800_53': True
            })

        main(**kwargs)

    cli()
