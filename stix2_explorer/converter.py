from concurrent.futures import ThreadPoolExecutor
import copy
import dataclasses
import json
import sys
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple, Union
import networkx as nx
from stix2.datastore import DataSource
from dataclasses import dataclass
import re
from typing import Iterable, List
import os
import requests
from stix2 import (
    FileSystemSource,
    MemoryStore,
    MemorySource,
    CompositeDataSource,
)
from stix2.datastore import DataStoreMixin
from stix2 import Filter
from typing import Iterable, Union
import networkx.readwrite.json_graph as json_graph
from dataclasses import dataclass
from stix2.serialization import STIXJSONEncoder as _JSONEncoder
from stix2.base import _STIXBase
from stix2.utils import STIXdatetime
from urllib.parse import urlparse


UUID_NAMESPACE = "7ab40379-3225-406f-8872-a1c24bc229d2"

CREATED_BY = "created-by"
MODIFIED_BY = "modified-by"
RELATED_TO = "related-to"
APPLIES_TO = "applies-to"
COMPONENT_OF = "component-of"

KEYS_TO_DROP = {
    "object_marking_refs",
    "created_by_ref",
    "x_mitre_version",
    "revoked",
    "x_mitre_attack_spec_version",
    "x_mitre_modified_by_ref",
    "x_mitre_deprecated",
    "x_mitre_data_source_ref",
}


class JSONEncoder(_JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, nx.DiGraph):
            return json_graph.node_link_data(o)
        elif dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        elif isinstance(o, _STIXBase):
            return dict(o)
        elif isinstance(o, STIXdatetime):
            return o.isoformat()
        elif iter(o) == o:
            return list(o)
        else:
            return super().default(o)


def iter_stix2_objects(
    data_source: Union[str, MemoryStore, DataSource],
    stix2_filters: Optional[Iterable[Union[str, Filter]]] = None,
    ignore_deprecated: bool = True,
    ignore_revoked: bool = True,
) -> Iterator[dict]:
    if stix2_filters:
        stix2_filters = parse_stix2_filters(stix2_filters)
    rows = data_source.query(stix2_filters)
    rows = stix2_objects_to_dicts(
        filter_stix2_objects(
            rows,
            ignore_deprecated=ignore_deprecated,
            ignore_revoked=ignore_revoked,
        )
    )
    yield from rows


def filter_stix2_objects(
    objects: Iterable[Any],
    ignore_deprecated: bool = True,
    ignore_revoked: bool = True,
) -> Iterator[Any]:
    if ignore_deprecated:
        objects = filter(lambda o: o.get("x_mitre_deprecated") is not True, objects)
        objects = filter(
            lambda o: o.get("x_capec_status", "").lower() != "deprecated", objects
        )

    if ignore_revoked:
        objects = filter(lambda o: o.get("revoked") is not True, objects)

    yield from objects


def stix2_objects_to_networkx(
    objects: Iterable[Any],
    add_created_by_ref: bool = False,
    add_modified_by_ref: bool = False,
    add_markings: bool = False,
    ignore_deprecated: bool = True,
    ignore_revoked: bool = True,
) -> nx.DiGraph:
    """
    Creates a nx.DiGraph from a list of STIX 2 objects.
    """
    g = nx.DiGraph()
    objects = stix2_objects_to_dicts(
        filter_stix2_objects(
            objects,
            ignore_deprecated=ignore_deprecated,
            ignore_revoked=ignore_revoked,
        )
    )
    for o in objects:
        stix2_id = o["id"]
        stix2_type = o["type"]

        if stix2_type not in ["relationship", "external_reference"]:
            g.add_node(stix2_id)

        if stix2_type == "relationship":
            g.add_edge(
                o["source_ref"],
                o["target_ref"],
                relationship_type=o["relationship_type"],
            )
        elif stix2_type == "x-mitre-data-component":
            data_source_id = o["x_mitre_data_source_ref"]
            g.add_edge(data_source_id, stix2_id, relationship_type=COMPONENT_OF)

        if add_created_by_ref:
            created_by = o.get("created_by_ref")
            if created_by:
                g.add_edge(stix2_id, created_by, relationship_type=CREATED_BY)

        if add_modified_by_ref:
            modified_by = o.get("x_mitre_modified_by_ref")
            if modified_by:
                g.add_edge(stix2_id, modified_by, relationship_type=MODIFIED_BY)

        if add_markings:
            marking_refs = o.get("object_marking_refs")
            if marking_refs:
                for marking_ref in marking_refs:
                    g.add_edge(marking_ref, stix2_id, relationship_type=APPLIES_TO)
    return g


def networkx_to_dot(g: nx.DiGraph) -> str:
    lines = []
    lines.append("digraph {")

    # Nodes
    for _, o in g.nodes(data=True):
        if o["type"] == "marking-definition":
            continue

        object_id = o["id"].replace("-", "_")
        label = o["name"]
        lines.append(f'  {object_id} [label="{label}"]')

    lines.append("")

    # Edges
    for a, b in g.edges:
        a = a.replace("-", "_")
        b = b.replace("-", "_")
        lines.append(f"  {a} -> {b}")
    lines.append("}")

    return "\n".join(lines)


def get_alias_map(
    rows: Iterable[Union[dict, _STIXBase]],
    include_names: bool = True,
    lowercase: bool = True,
) -> Dict[str, str]:
    m = {}
    for o in rows:
        stix2_id = o["id"]

        if include_names:
            name = o.get("name")
            if name is not None:
                m[name] = stix2_id

            for alias in o.get("x_mitre_aliases", []):
                m[alias] = stix2_id

        for external_reference in o.get("external_references", []):
            source_name = external_reference.get("source_name")
            if source_name is not None and source_name in ["capec", "mitre-attack"]:
                external_id = external_reference["external_id"]
                m[external_id] = stix2_id

    if lowercase:
        m = {k.lower(): v for k, v in m.items()}
    return m


def get_data_source(
    data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]]
) -> Union[DataSource, CompositeDataSource]:
    if isinstance(data_sources, (str, DataSource)):
        return _get_data_source(data_sources)
    else:
        data_sources = [_get_data_source(ds) for ds in data_sources]
        composite_data_source = CompositeDataSource()
        composite_data_source.add_data_sources(data_sources)
        return composite_data_source


def _get_data_source(path: str) -> DataSource:
    if os.path.exists(path):
        if os.path.isdir(path):
            return FileSystemSource(path)
        else:
            return _get_memory_source_from_file(path)
    elif path.startswith(("http://", "https://")):
        return _get_memory_source_from_web(path)
    else:
        raise ValueError(f"Invalid path: {path}")


def _get_memory_source_from_file(path: str) -> MemoryStore:
    with open(path, "rb") as file:
        stix_data = json.load(file)
        return MemorySource(stix_data=stix_data)


def _get_memory_source_from_web(url: str) -> MemoryStore:
    response = requests.get(url)
    response.raise_for_status()
    return MemorySource(response.json()["objects"])


def parse_stix2_filters(stix2_filters: Iterable[Union[str, Filter]]) -> List[Filter]:
    return [parse_stix2_filter(f) for f in stix2_filters]


def parse_stix2_filter(stix2_filter: str) -> Filter:
    """
    The following operators are supported:

    - '='
    - '!='
    - 'in'
    - '>'
    - '<'
    - '>='
    - '<='
    - 'contains'

    Examples:

    - 'type = relationship'
    """
    m = re.match(r"(.+) (.+) (.+)", stix2_filter)
    if m:
        k, o, v = m.groups()
        return Filter(k, o, v)


def realpath(path: str) -> str:
    path = os.path.expanduser(path)
    path = os.path.realpath(path)
    return path


def stix2_objects_to_dicts(rows: Iterable[Any]) -> Iterator[dict]:
    for row in rows:
        if isinstance(row, dict):
            yield row
        else:
            yield stix2_objects_to_dict(row)


def stix2_objects_to_dict(o: Any) -> dict:
    if isinstance(o, _STIXBase):
        b = json.dumps(o, cls=JSONEncoder)
        o = json.loads(b)
    elif isinstance(o, dict):
        pass
    else:
        raise ValueError(f"Unsupported object type: {type(o).__name__}")
    return o


@dataclass()
class DiGraphSummary:
    total_nodes: int
    total_edges: int

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def summarize_digraph(g: nx.DiGraph) -> DiGraphSummary:
    return DiGraphSummary(
        total_nodes=g.number_of_nodes(),
        total_edges=g.number_of_edges(),
    )


def nx_digraph_to_triples(g: nx.DiGraph) -> Iterator[Tuple[str, str, str]]:
    triples = _nx_digraph_to_triples(g)
    yield from sorted(triples)


def _nx_digraph_to_triples(g: nx.DiGraph) -> Iterator[Tuple[str, str, str]]:
    for a, b, data in g.edges(data=True):
        label = data.get("relationship_type")
        if not label:
            continue

        yield a, label, b
