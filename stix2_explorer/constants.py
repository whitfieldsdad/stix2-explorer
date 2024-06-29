# UUIDv5 namespace from STIX 2.1 specification
# - See: https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070594
UUID_NAMESPACE = '00abedb4-aa42-466c-9c01-fed23315a9b7'

MITRE_ATTACK_FOR_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
MITRE_ATTACK_FOR_MOBILE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"
MITRE_ATTACK_FOR_ICS_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"
NIST_SP_800_53_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-controls.json"
MITRE_ATTACK_FOR_ENTERPRISE_TO_NIST_SP_800_53_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-mappings.json"
MITRE_CAPEC_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
MITRE_MBC_URL = "https://raw.githubusercontent.com/MBCProject/mbc-stix2/master/mbc/mbc.json"

MITRE_ATTACK_FOR_ENTERPRISE = 'MITRE ATT&CK for Enterprise'
MITRE_ATTACK_FOR_MOBILE = 'MITRE ATT&CK for Mobile'
MITRE_ATTACK_FOR_ICS = 'MITRE ATT&CK for ICS'
MITRE_CAPEC = 'MITRE CAPEC'
MITRE_MBC = 'MITRE MBC'
NIST_SP_800_53 = 'NIST SP 800-53'
MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53 = 'MITRE ATT&CK for Enterprise to NIST SP 800-53'

DATA_SOURCE_URLS = {
    MITRE_ATTACK_FOR_ENTERPRISE: MITRE_ATTACK_FOR_ENTERPRISE_URL,
    MITRE_ATTACK_FOR_MOBILE: MITRE_ATTACK_FOR_MOBILE_URL,
    MITRE_ATTACK_FOR_ICS: MITRE_ATTACK_FOR_ICS_URL,
    MITRE_CAPEC: MITRE_CAPEC_URL,
    MITRE_MBC: MITRE_MBC_URL,
    NIST_SP_800_53: NIST_SP_800_53_URL,
    MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53: MITRE_ATTACK_FOR_ENTERPRISE_TO_NIST_SP_800_53_URL,
}

BLACK = "#000000"
AQUA  = '#00FFFF'
AQUAMARINE = '#7FFFD4'
CORNFLOWER_BLUE = '#6495ED'
DARK_MAGENTA = '#8B008B'
DEEP_SKY_BLUE = '#00BFFF'
FOREST_GREEN = '#228B22'
GOLD    = '#FFD700'
HOT_PINK  = '#FF69B4'
LIGHT_GREEN = '#90EE90'
MAGENTA = '#FF00FF'
ORANGE_RED = '#FF4500'
PINK     = '#FFC0CB'
PLUM  = '#DDA0DD'
RED     = '#FF0000'
MEDIUM_PURPLE = '#9370DB'
BLUE = '#0000FF'
MEDIUM_SEA_GREEN = '#3CB371'

ATTACK_PATTERN = 'attack-pattern'
CAMPAIGN = 'campaign'
COURSE_OF_ACTION = 'course-of-action'
IDENTITY = 'identity'
INTRUSION_SET = 'intrusion-set'
MALWARE = 'malware'
MALWARE_BEHAVIOR = 'malware-behavior'
MALWARE_METHOD = 'malware-method'
MALWARE_OBJECTIVE = 'malware-objective'
MARKING_DEFINITION = 'marking-definition'
TOOL = 'tool'
X_MITRE_ASSET = 'x-mitre-asset'
X_MITRE_DATA_COMPONENT = 'x-mitre-data-component'
X_MITRE_DATA_SOURCE = 'x-mitre-data-source'
X_MITRE_MATRIX = 'x-mitre-matrix'
X_MITRE_TACTIC = 'x-mitre-tactic'
EXTERNAL_REFERENCE = 'external-reference'

DEFAULT_COLORS_BY_TYPE = {
    ATTACK_PATTERN: AQUA,
    CAMPAIGN: MEDIUM_PURPLE,
    COURSE_OF_ACTION: FOREST_GREEN,
    IDENTITY: DARK_MAGENTA,
    INTRUSION_SET: DEEP_SKY_BLUE,
    MALWARE: RED,
    MALWARE_BEHAVIOR: ORANGE_RED,
    MALWARE_METHOD: PINK,
    MALWARE_OBJECTIVE: GOLD,
    MARKING_DEFINITION: PLUM,
    TOOL: HOT_PINK,
    X_MITRE_ASSET: AQUAMARINE,
    X_MITRE_DATA_COMPONENT: LIGHT_GREEN,
    X_MITRE_DATA_SOURCE: MAGENTA,
    X_MITRE_MATRIX: CORNFLOWER_BLUE,
    X_MITRE_TACTIC: BLUE,
    EXTERNAL_REFERENCE: MEDIUM_SEA_GREEN,
}
