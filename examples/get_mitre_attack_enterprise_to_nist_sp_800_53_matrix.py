import sys
from typing import Dict, Optional
from stix2_explorer import converter
from stix2.datastore import DataSource
import polars as pl
import urllib3

# TLS certificate validation is disabled.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MITRE_ATTACK_ENTERPRISE_ID = "mitre-attack-enterprise"
MITRE_ATTACK_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

NIST_SP_800_53_ID = "nist-sp-800-53-r5"
NIST_SP_800_53_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-controls.json"

MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-mappings.json"
MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53_ID = (
    "mitre-attack-enterprise-to-nist-sp-800-53"
)


def main(output_path: Optional[str]):
    mitre_attack_enterprise = converter.get_stix2_data_source(
        MITRE_ATTACK_ENTERPRISE_URL
    )
    nist_sp_800_53 = converter.get_stix2_data_source(NIST_SP_800_53_URL)
    mitre_attack_enterprise_to_nist_sp_800_53 = converter.get_stix2_data_source(
        MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53_URL
    )

    # Keep track of where each object came from.
    mitre_attack_enterprise_objects = {o["id"] for o in mitre_attack_enterprise.query()}
    nist_sp_800_53_objects = {o["id"] for o in nist_sp_800_53.query()}

    # The composite data source will be used to identify relationships across the entire graph.
    composite_data_source = converter.get_stix2_data_source(
        data_sources=[
            mitre_attack_enterprise,
            nist_sp_800_53,
            mitre_attack_enterprise_to_nist_sp_800_53,
        ]
    )

    rows = list(composite_data_source.query())
    g = converter.convert_stix2_objects_to_digraph(rows)

    rows = []
    nodes = dict(g.nodes(data=True))
    for source_object_id, target_object_id, data in g.edges(data=True):
        source_object_external_id = None
        try:
            source_object_external_id = converter.get_external_id(
                nodes[source_object_id]
            )
        except (KeyError, ValueError):
            pass

        target_object_external_id = None
        try:
            target_object_external_id = converter.get_external_id(
                nodes[target_object_id]
            )
        except (KeyError, ValueError):
            pass

        if source_object_id in mitre_attack_enterprise_objects:
            source_dataset = MITRE_ATTACK_ENTERPRISE_ID
        elif source_object_id in nist_sp_800_53_objects:
            source_dataset = NIST_SP_800_53_ID
        else:
            continue

        if target_object_id in mitre_attack_enterprise_objects:
            target_dataset = MITRE_ATTACK_ENTERPRISE_ID
        elif target_object_id in nist_sp_800_53_objects:
            target_dataset = NIST_SP_800_53_ID
        else:
            continue

        relationship = data["label"]
        row = {
            "source_dataset": source_dataset,
            "source_object_id": source_object_id,
            "source_object_external_id": source_object_external_id,
            "source_object_name": nodes[source_object_id].get("name"),
            "source_object_type": converter.get_stix2_type_from_id(source_object_id),
            "relationship": relationship,
            "target_object_id": target_object_id,
            "target_object_external_id": target_object_external_id,
            "target_object_name": nodes[target_object_id].get("name"),
            "target_object_type": converter.get_stix2_type_from_id(target_object_id),
            "target_dataset": target_dataset,
        }
        rows.append(row)

    df = pl.DataFrame(rows)
    df = df.filter(df["source_dataset"] == NIST_SP_800_53_ID)

    if not output_path:
        output_path = sys.stdout
    df.write_csv(output_path)


if __name__ == "__main__":

    def cli():
        import argparse

        parser = argparse.ArgumentParser(
            "Get MITRE ATT&CK to NIST SP 800-53 relationship matrix"
        )
        parser.add_argument(
            "--output-path",
            "-o",
            help="Output file (CSV)",
            type=str,
            default=None,
        )
        kwargs = vars(parser.parse_args())
        main(**kwargs)

    cli()
