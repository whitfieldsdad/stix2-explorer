<!-- omit in toc -->
# stix2-explorer

A Python library for exploring STIX 2 content as [directed acyclic graphs (DAGs)](https://en.wikipedia.org/wiki/Directed_acyclic_graph) using [networkx](https://github.com/networkx/networkx) and [GraphViz](https://graphviz.org/).

## Features

- Provides a simple and intuitive command line interface that allows you to explore arbitrary STIX 2 content as a directed acyclic graph (DAG)
- Allows you to automatically download new STIX 2 content from MITRE and OASIS through GitHub.

## Usage

### Example data sources

| Data source                                        | Format | URL                                                                                                                                                                                                                                                       |
| -------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MITRE ATT&CK for Enterprise                        | STIX 2 | [mitre-attack/attack-stix-data](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json)                                                                                                          |
| MITRE ATT&CK for Mobile                            | STIX 2 | [mitre-attack/attack-stix-data](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json)                                                                                                                  |
| MITRE ATT&CK for ICS                               | STIX 2 | [mitre-attack/attack-stix-data](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json)                                                                                                                        |
| MITRE CAPEC                                        | STIX 2 | [mitre/cti](https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json)                                                                                                                                                                 |
| MITRE MBC                                          | STIX 2 | [MBCProject/mbc-stix2.1](https://raw.githubusercontent.com/MBCProject/mbc-stix2.1/master/mbc/mbc.json)                                                                                                                                                    |
| OASIS CTI STIX 2 Common Objects                    | STIX 2 | [oasis-open/cti-stix-common-objects](https://github.com/oasis-open/cti-stix-common-objects)                                                                                                                                                               |
| MITRE ATT&CK to NIST SP 800-53 Revision 4 mappings | STIX 2 | [center-for-threat-informed-defense/attack-control-framework-mappings](https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r4/stix/nist800-53-r4-mappings.json) |
| MITRE ATT&CK to NIST SP 800-53 Revision 5 mappings | STIX 2 | [center-for-threat-informed-defense/attack-control-framework-mappings](https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-mappings.json) |
| NIST SP 800-53 Revision 4                          | STIX 2 | [center-for-threat-informed-defense/attack-control-framework-mappings](https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r4/stix/nist800-53-r4-controls.json) |
| NIST SP 800-53 Revision 5                          | STIX 2 | [center-for-threat-informed-defense/attack-control-framework-mappings](https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-controls.json) |  |

## Additional resources

- [STIX 2.1 specification](https://oasis-open.github.io/cti-documentation/)
- [MITRE ATT&CK STIX 2 content user guide](https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md)
- [MITRE CAPEC STIX 2 content user guide](https://github.com/mitre/cti/blob/master/USAGE-CAPEC.md)
