import sys
from typing import Optional
from stix2_explorer import converter
import polars as pl
import urllib3

# TLS certificate validation is disabled.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/frameworks/attack_12_1/nist800_53_r5/stix/nist800-53-r5-controls.json"


def main(output_path: Optional[str]):
    src = converter.get_stix2_data_source(URL)
    rows = list(src.query())
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

        relationship = data["label"]
        row = {
            "source_object_id": source_object_id,
            "source_object_external_id": source_object_external_id,
            "source_object_name": nodes[source_object_id].get("name"),
            "source_object_type": converter.get_stix2_type_from_id(source_object_id),
            "relationship": relationship,
            "target_object_id": target_object_id,
            "target_object_external_id": target_object_external_id,
            "target_object_name": nodes[target_object_id].get("name"),
            "target_object_type": converter.get_stix2_type_from_id(target_object_id),
        }
        rows.append(row)

    df = pl.DataFrame(rows)

    if not output_path:
        output_path = sys.stdout
    df.write_csv(output_path)


if __name__ == "__main__":

    def cli():
        import argparse

        parser = argparse.ArgumentParser("Get NIST SP 800-53 relationship matrix")
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
