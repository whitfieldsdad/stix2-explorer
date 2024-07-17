from typing import Iterable, Optional
from stix2_explorer import converter

import networkx as nx
import urllib3
import sys


# TLS certificate validation is disabled.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main(input_paths: Iterable[str], output_path: Optional[str]):
    src = converter.get_stix2_data_source(input_paths)
    rows = converter.iter_stix2_objects(src)

    g = converter.convert_stix2_objects_to_digraph(rows)
    m = {}
    for edge in g.edges:
        s, o = edge
        for v in (s, o):
            m[v] = converter.get_stix2_type_from_id(v)

    g = nx.relabel_nodes(g, m, copy=False)
    triples = converter.convert_digraph_to_triples(g)
    dot = converter.convert_triples_to_dot(triples)

    if output_path:
        with open(output_path, "w") as f:
            f.write(dot)
    else:
        print(dot)


if __name__ == "__main__":

    def cli():
        import argparse

        parser = argparse.ArgumentParser(
            "Visualize the relationships within one or more STIX 2 bundles"
        )
        parser.add_argument(
            "--input-path",
            "-i",
            nargs="+",
            required=True,
            dest="input_paths",
            help="Input file (STIX 2 bundle)",
        )
        parser.add_argument(
            "--output-path",
            "-o",
            help="Output path (DOT)",
        )
        kwargs = vars(parser.parse_args())
        main(**kwargs)

    cli()
