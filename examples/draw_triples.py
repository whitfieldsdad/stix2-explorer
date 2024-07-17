from typing import Optional
from stix2_explorer import converter

import sys


def main(output_path: Optional[str]):
    triples = list(map(lambda x: x.strip().split(","), sys.stdin))
    dot = converter.convert_triples_to_dot(triples)
    if output_path:
        with open(output_path, "w") as f:
            f.write(dot)
    else:
        print(dot)


if __name__ == "__main__":

    def cli():
        import argparse

        parser = argparse.ArgumentParser("Convert triples into a DOT file")
        parser.add_argument(
            "--output-path",
            "-o",
            type=str,
            help="Output path (DOT)",
        )
        kwargs = vars(parser.parse_args())
        main(**kwargs)

    cli()
