import sys
from typing import Iterator, Optional, Tuple
from neo4j import Driver, GraphDatabase

from stix2_explorer import converter
import logging
import urllib3

# Disable warnings about insecure TLS connections.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

Triple = Tuple[str, str, str]


def main(
    include: list[str],
    neo4j_uri: str,
    neo4j_username: Optional[str],
    neo4j_password: Optional[str],
):
    src = converter.get_stix2_data_source(include)

    rows = list(src.query())
    g = converter.convert_stix2_objects_to_digraph(rows)
    triples = converter.convert_digraph_to_triples(g)

    driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_username, neo4j_password))
    if not test_connection(driver):
        sys.exit(1)

    insert_triples(driver, triples)


def insert_triples(driver: Driver, triples: Iterator[Triple], collection: str):
    def insert_triple(tx, s: str, p: str, o: str):
        q = (
            "MERGE (s:Entity {name: $s}) "
            "MERGE (o:Entity {name: $o}) "
            "MERGE (s)-[r:RELATION {type: $p}]->(o)"
        )
        tx.run(q, s=s, p=p, o=o)

    triples = set(triples)
    with driver.session() as session:
        for s, p, o in triples:
            session.write_transaction(insert_triple, s, p, o)


def test_connection(driver: Driver) -> bool:
    with driver.session() as session:
        _ = session.run("RETURN 'Hello, Neo4j!' AS message").single()


if __name__ == "__main__":

    def cli():
        import argparse

        parser = argparse.ArgumentParser(description="Import STIX2 content into Neo4j.")
        parser.add_argument(
            "--include",
            "-i",
            type=str,
            required=True,
            nargs="+",
            help="Path/URL to STIX 2 bundle(s) to import",
        )
        parser.add_argument(
            "--neo4j-uri",
            default="bolt://localhost:7687",
        )
        parser.add_argument(
            "--neo4j-username",
            default="neo4j",
        )
        parser.add_argument(
            "--neo4j-password",
            default="password",
        )
        kwargs = vars(parser.parse_args())
        main(**kwargs)

    cli()
