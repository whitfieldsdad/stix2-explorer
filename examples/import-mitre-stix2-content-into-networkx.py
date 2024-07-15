from stix2_explorer.decoders import GenericDecoder, MitreDecoder
from stix2_explorer import util
from examples.constants import *

import urllib3

# We ignore TLS certificate verification to improve stability.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

attack = util.get_data_source_with_fallback(ATTACK_ENTERPRISE_PATH, ATTACK_ENTERPRISE_URL)
capec = util.get_data_source_with_fallback(CAPEC_PATH, CAPEC_URL)
mbc = util.get_data_source(MITRE_MBC_URL)
nist_sp_800_53 = util.get_data_source_with_fallback(NIST_SP_800_53_PATH, NIST_SP_800_53_URL)
attack_to_nist_sp_800_53 = util.get_data_source_with_fallback(MITRE_ATTACK_TO_NIST_SP_800_53_PATH, MITRE_ATTACK_TO_NIST_SP_800_53_URL)

src = util.get_data_source([
    attack, 
    capec, 
    mbc,
    nist_sp_800_53,
    attack_to_nist_sp_800_53,
])
g = util.convert_stix2_objects_to_digraph(
    objects=src.query(),
    decoders=[GenericDecoder(), MitreDecoder()]
)
