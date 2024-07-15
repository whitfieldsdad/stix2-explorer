from dataclasses import dataclass
import datetime
from typing import Iterator, Optional, Tuple
import uuid

import jcs
from stix2_explorer.constants import EXTERNAL_REFERENCE


RELATED_TO = "related-to"

ADD_IDENTITIES = False
ADD_MARKINGS = False
EXPAND_EXTERNAL_REFERENCES = False


@dataclass()
class Node:
    id: str
    type: str
    data: Optional[dict] = None

    def __iter__(self):
        yield from (
            self.id,
            self.type,
            self.data,
        )


@dataclass()
class Edge:
    source: str
    predicate: str
    object: str
    data: Optional[dict] = None

    def to_triple(self) -> Tuple[str, str, str]:
        return self.source, self.predicate, self.object

    def __iter__(self):
        yield from (
            self.source,
            self.predicate,
            self.object,
            self.data,
        )


@dataclass()
class Decoder:
    add_identities: bool = ADD_IDENTITIES
    add_markings: bool = ADD_MARKINGS
    expand_external_references: bool = EXPAND_EXTERNAL_REFERENCES

    def iter_nodes(self, rows: Iterator[dict]) -> Iterator[Node]:
        """
        Decode a stream of rows into a stream of nodes.
        """
        for object_id, object_type, o in self._iter_nodes(rows):
            yield Node(
                id=object_id,
                type=object_type,
                data=o,
            )

    def _iter_nodes(self, rows: Iterator[dict]) -> Iterator[Tuple[str, str, Optional[dict]]]:
        for o in rows:
            if self.expand_external_references:
                for external_reference in o.get('external_references', []):
                    url = external_reference.get('url')
                    if url:
                        external_reference_id = get_uuid5({'url': url})
                        yield external_reference_id, EXTERNAL_REFERENCE, external_reference

            object_type = o['type']
            if object_type == 'relationship':
                continue

            elif object_type == 'identity' and not self.add_identities:
                continue

            elif object_type == 'marking-definition' and not self.add_markings:
                continue

            elif object_type == 'external-reference' and not self.expand_external_references:
                continue

            yield o['id'], o['type'], o

    def iter_edges(self, rows: Iterator[dict]) -> Iterator[Edge]:
        """
        Decode a stream of rows into a stream of edges.
        """
        raise NotImplementedError()
    
    def iter_triples(self, rows: Iterator[dict]) -> Iterator[Tuple[str, str, str]]:
        """
        Decode a stream of rows into a stream of triples.
        """
        for edge in self.iter_edges(rows):
            yield edge.to_triple()

    def is_deprecated(self, o: dict) -> bool:
        """
        Return True if the object is deprecated.
        """
        return False
    
    def is_revoked(self, o: dict) -> bool:
        """
        Return True if the object is revoked.
        """
        return o.get('revoked') is True


@dataclass()
class GenericDecoder(Decoder):
    """
    A generic streaming decoder for STIX 2 objects.
    """
    def iter_edges(self, rows: Iterator[dict]) -> Iterator[Edge]:
        for o in rows:
            stix2_id = o["id"]
            stix2_type = o["type"]

            if stix2_type == "relationship":
                created = parse_timestamp(o.get("created"))
                modified = parse_timestamp(o.get("modified"))
                yield Edge(
                    source=o["source_ref"],
                    predicate=o["relationship_type"],
                    object=o["target_ref"],
                    data={
                        "created": created,
                        "modified": modified,
                    },
                )
                continue
            
            if self.add_identities:
                created_by = o.get("created_by_ref")
                if created_by:
                    yield Edge(
                        source=stix2_id,
                        predicate=RELATED_TO,
                        object=created_by,
                    )

            if self.add_markings:
                marking_refs = o.get("object_marking_refs")
                if marking_refs:
                    for marking_ref in marking_refs:
                        yield Edge(
                            source=stix2_id,
                            predicate=RELATED_TO,
                            object=marking_ref,
                        )
            
            if self.expand_external_references:
                for ref in o.get("external_references", []):
                    url = ref.get('url')
                    if url:
                        external_reference_id = get_uuid5({'url': url})
                        yield Edge(
                            source=stix2_id,
                            predicate=RELATED_TO,
                            object=external_reference_id,
                        )


@dataclass()
class MitreDecoder(Decoder):
    """
    A decoder which includes support for MITRE's extended STIX 2 format (i.e. for ATT&CK, CAPEC, and MBC).
    """
    def iter_edges(self, rows: Iterator[dict]) -> Iterator[Edge]:
        rows = list(rows)

        kill_chain_phases_to_tactics = {}
        for o in rows:
            if o["type"] == "x-mitre-tactic":
                k = o["x_mitre_shortname"]
                kill_chain_phases_to_tactics[k] = o['id']

        for o in rows:
            stix2_type = o["type"]
            if stix2_type == 'relationship':
                continue

            stix2_id = o["id"]

            if stix2_type == "x-mitre-matrix":
                for tactic_id in o["tactic_refs"]:
                    yield Edge(
                        source=tactic_id,
                        predicate=RELATED_TO,
                        object=stix2_id,
                    )

            elif stix2_type == "attack-pattern":
                for k in o.get("kill_chain_phases", []):
                    yield Edge(
                        source=stix2_id,
                        predicate=RELATED_TO,
                        object=kill_chain_phases_to_tactics[k["phase_name"]],
                    )

            elif stix2_type == "x-mitre-data-component":
                yield Edge(
                    source=o["x_mitre_data_source_ref"],
                    predicate=RELATED_TO,
                    object=stix2_id,
                )
            
            elif stix2_type == 'malware-behavior':
                for ref in o['objective_refs']:
                    yield Edge(
                        source=stix2_id,
                        predicate=RELATED_TO,
                        object=ref,
                    )
            
            elif stix2_type == 'malware-method':
                yield Edge(
                    source=stix2_id,
                    predicate=RELATED_TO,
                    object=o['behavior_ref'],
                )

            if self.add_identities:
                modified_by = o.get("x_mitre_modified_by_ref")
                if modified_by:
                    yield Edge(
                        source=stix2_id,
                        predicate=RELATED_TO,
                        object=modified_by,
                    )
    
    def is_deprecated(self, o: dict) -> bool:
        return o.get("x_mitre_deprecated") is True or o.get("x_capec_status", "").lower() == "deprecated"


def parse_timestamp(t: Optional[str]) -> Optional[datetime.datetime]:
    if t is not None:
        return datetime.datetime.fromisoformat(t)


def get_uuid5(data: dict) -> str:
    namespace = uuid.UUID(UUID_NAMESPACE)
    blob = jcs.canonicalize(data).decode('utf-8')
    return str(uuid.uuid5(namespace, blob))
