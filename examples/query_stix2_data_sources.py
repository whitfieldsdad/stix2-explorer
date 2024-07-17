import json

from stix2_explorer import converter
import logging
import urllib3

from stix2_explorer.serialization import JSONEncoder

# Disable warnings about insecure TLS connections.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def main(
    include: list[str],
):
    src = converter.get_stix2_data_source(include)

    for row in src.query():
        print(json.dumps(row, cls=JSONEncoder))


if __name__ == "__main__":

    def cli():
        import argparse

        parser = argparse.ArgumentParser(description="Query STIX 2 content")
        parser.add_argument(
            "--include",
            "-i",
            type=str,
            required=True,
            nargs="+",
            help="Path/URL to STIX 2 bundle(s)",
        )
        kwargs = vars(parser.parse_args())
        main(**kwargs)

    cli()
