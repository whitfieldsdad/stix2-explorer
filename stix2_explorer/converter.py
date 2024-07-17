import collections
from dataclasses import dataclass
import concurrent.futures
import datetime
import fnmatch
import glob
import itertools
import os
import re
import sys
import tempfile
from typing import (
    Any,
    Callable,
    List,
    Optional,
    Tuple,
    Iterable,
    Iterator,
    Dict,
    Union,
)
import uuid
import jcs
import networkx as nx

import requests
from stix2.base import _STIXBase
from stix2.datastore import DataSource
import json
import networkx as nx

from stix2_explorer.constants import (
    DEFAULT_COLORS_BY_NODE_TYPE,
    DOT_INDENT,
    UUID_NAMESPACE,
    Triple,
)

import logging
from stix2 import (
    MemoryStore,
    MemorySource,
    CompositeDataSource,
)
from stix2_explorer.serialization import JSONEncoder

logger = logging.getLogger(__name__)

RELATED_TO = "related-to"

INCLUDE_IDENTITIES = False
INCLUDE_MARKINGS = False


@dataclass()
class Node:
    id: str
    type: str
    data: dict

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

    def to_triple(self) -> Tuple[str, str, str]:
        return self.source, self.predicate, self.object

    def __iter__(self):
        yield from (
            self.source,
            self.predicate,
            self.object,
        )


@dataclass()
class Decoder:
    include_identities: bool = INCLUDE_IDENTITIES
    include_markings: bool = INCLUDE_MARKINGS

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
        return o.get("revoked") is True

    def iter_names(self, o: dict) -> Iterator[str]:
        names = set()
        name = o.get("name")
        if name:
            names.add(name)

        aliases = o.get("aliases")
        if aliases:
            names |= set(aliases)

        yield from sorted(names)


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
                yield Edge(
                    source=o["source_ref"],
                    predicate=o["relationship_type"],
                    object=o["target_ref"],
                )
                continue

            if self.include_identities:
                created_by = o.get("created_by_ref")
                if created_by:
                    yield Edge(
                        source=stix2_id,
                        predicate=RELATED_TO,
                        object=created_by,
                    )

            if self.include_markings:
                marking_refs = o.get("object_marking_refs")
                if marking_refs:
                    for marking_ref in marking_refs:
                        yield Edge(
                            source=stix2_id,
                            predicate=RELATED_TO,
                            object=marking_ref,
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
                kill_chain_phases_to_tactics[k] = o["id"]

        for o in rows:
            stix2_type = o["type"]
            if stix2_type == "relationship":
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
                    try:
                        yield Edge(
                            source=stix2_id,
                            predicate=RELATED_TO,
                            object=kill_chain_phases_to_tactics[k["phase_name"]],
                        )
                    except KeyError:
                        continue

            elif stix2_type == "x-mitre-data-component":
                yield Edge(
                    source=o["x_mitre_data_source_ref"],
                    predicate=RELATED_TO,
                    object=stix2_id,
                )

            elif stix2_type == "malware-behavior":
                for ref in o["objective_refs"]:
                    yield Edge(
                        source=stix2_id,
                        predicate=RELATED_TO,
                        object=ref,
                    )

            elif stix2_type == "malware-method":
                yield Edge(
                    source=stix2_id,
                    predicate=RELATED_TO,
                    object=o["behavior_ref"],
                )

            if self.include_identities:
                modified_by = o.get("x_mitre_modified_by_ref")
                if modified_by:
                    yield Edge(
                        source=stix2_id,
                        predicate=RELATED_TO,
                        object=modified_by,
                    )

    def is_deprecated(self, o: dict) -> bool:
        return (
            o.get("x_mitre_deprecated") is True
            or o.get("x_capec_status", "").lower() == "deprecated"
        )


def get_default_decoders(
    include_identities: bool = INCLUDE_IDENTITIES,
    include_markings: bool = INCLUDE_MARKINGS,
) -> Iterable[Decoder]:

    return [
        GenericDecoder(
            include_identities=include_identities,
            include_markings=include_markings,
        ),
        MitreDecoder(
            include_identities=include_identities,
            include_markings=include_markings,
        ),
    ]


def iter_stix2_objects(
    data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]],
    object_ids: Optional[Iterable[str]] = None,
    object_types: Optional[Iterable[str]] = None,
    object_names: Optional[Iterable[str]] = None,
    decoders: Optional[Iterable[Decoder]] = None,
    include_deprecated: bool = False,
    include_revoked: bool = False,
) -> Iterator[dict]:

    src = get_stix2_data_source(data_sources)
    rows = map(convert_stix2_object_to_dict, src.query())

    rows = filter_stix2_objects(
        rows=rows,
        object_ids=object_ids,
        object_types=object_types,
        object_names=object_names,
        decoders=decoders,
        include_deprecated=include_deprecated,
        include_revoked=include_revoked,
    )
    yield from rows


def filter_stix2_objects(
    rows: Iterable[Any],
    object_ids: Optional[Iterable[str]] = None,
    object_types: Optional[Iterable[str]] = None,
    object_names: Optional[Iterable[str]] = None,
    decoders: Optional[Iterable[Decoder]] = None,
    include_deprecated: bool = False,
    include_revoked: bool = False,
) -> Iterator[Any]:

    decoders = decoders or get_default_decoders()
    for row in rows:
        if object_ids and row["id"] not in object_ids:
            continue

        if object_types and row["type"] not in object_types:
            continue

        if object_names:
            found = set(
                itertools.chain.from_iterable(d.iter_names(row) for d in decoders)
            )
            if not any_string_matches_any_pattern(found, object_names):
                continue

        if not include_deprecated and any(d.is_deprecated(row) for d in decoders):
            continue

        if not include_revoked and any(d.is_revoked(row) for d in decoders):
            continue

        yield row


def create_stix2_bundle(rows: Iterable[dict]) -> dict:
    bundle = {
        "id": f"bundle--{uuid.uuid4()}",
        "type": "bundle",
        "objects": list(rows),
        "spec_verson": "2.1",
    }
    return bundle


def any_string_matches_any_pattern(
    strings: Iterable[str], patterns: Iterable[str]
) -> bool:
    strings = set(map(str.lower, strings))
    patterns = set(map(str.lower, patterns))
    return any(fnmatch.fnmatch(s, p) for s in strings for p in patterns)


# TODO
def get_related_object_subgraph(
    g: nx.DiGraph,
    object_ids: Optional[Iterable[str]] = None,
    labels: Optional[Iterable[str]] = None,
    radius: Optional[int] = 1,
) -> nx.DiGraph:

    object_ids = object_ids or g.nodes()

    sg = nx.DiGraph()
    for _ in range(radius):
        for object_id in object_ids:
            in_edges = g.in_edges(object_id, data=True)
            out_edges = g.out_edges(object_id, data=True)

            for u, v, data in itertools.chain(in_edges, out_edges):
                if labels and not any_string_matches_any_pattern(
                    [data["label"]], labels
                ):
                    continue
                sg.add_edge(u, v, **data)

    return sg


def get_digraph_summary(g: nx.DiGraph) -> dict:
    return {
        "total_nodes": g.number_of_nodes(),
        "total_edges": g.number_of_edges(),
        "total_edges_by_type": tally_digraph_edges_by_type(g),
    }


def tally_digraph_edges_by_type(g: nx.DiGraph) -> Dict[str, int]:
    m = collections.defaultdict(int)
    for s, p, o in convert_digraph_to_triples(g):
        s = get_stix2_type_from_id(s)
        o = get_stix2_type_from_id(o)
        t = (s, p, o)
        k = ",".join(t)
        m[k] += 1
    return dict(m)


def convert_stix2_objects_to_digraph(
    rows: Iterable[Any],
    decoders: Optional[Iterable[Decoder]] = None,
    edge_label_key: str = "label",
) -> nx.DiGraph:

    rows = list(rows)

    if not decoders:
        decoders = [GenericDecoder(), MitreDecoder()]

    g = nx.DiGraph()
    for decoder in decoders:
        for edge in decoder.iter_edges(rows):
            edge_data = {edge_label_key: edge.predicate}
            g.add_edge(edge.source, edge.object, **edge_data)

    for o in rows:
        if o["id"] in g:
            g.add_node(o["id"], **o)

    return g


def relabel_nodes_by_external_id(rows: Iterable[dict], g: nx.DiGraph) -> nx.DiGraph:
    m = {}
    for o in rows:
        try:
            m[o["id"]] = get_external_id(o)
        except ValueError:
            continue

    g = g.subgraph(m.keys())
    g = nx.relabel_nodes(g, m, copy=True)
    return g


def dict_to_hint(o: dict) -> str:
    return ", ".join([f"{k}: {v}" for (k, v) in o.items()])


def _get_dot_safe_string(s: str) -> str:
    s = re.sub(r"[\W-]+", "_", s)
    s = s.lower()
    return s


def convert_stix2_objects_to_dicts(rows: Iterable[Any]) -> Iterable[dict]:
    for row in rows:
        yield convert_stix2_object_to_dict(row)


def convert_stix2_object_to_dict(o: Any) -> dict:
    if isinstance(o, _STIXBase):
        b = json.dumps(o, cls=JSONEncoder)
        o = json.loads(b)
    elif isinstance(o, dict):
        pass
    else:
        raise ValueError(f"Unsupported object type: {type(o).__name__}")
    return o


def convert_stix2_objects_to_triples(
    rows: Iterable[dict],
    node_labels: Optional[Union[str, Dict[str, str], Callable[[dict], str]]] = None,
    decoders: Optional[Iterable[Decoder]] = None,
) -> Iterable[Tuple[str, str, str]]:

    g = convert_stix2_objects_to_digraph(rows, decoders=decoders)
    return convert_digraph_to_triples(g)


def convert_digraph_to_triples(
    g: nx.DiGraph, predicate_attr: str = "label"
) -> Iterable[Triple]:

    for s, o, data in g.edges(data=True):
        p = data[predicate_attr]
        yield s, p, o


def convert_digraph_to_dot(
    g: nx.DiGraph,
    node_labels: Optional[Dict[str, str]] = None,
    include_edge_labels: bool = True,
    group_by_node_type: bool = False,
) -> str:

    indent = " " * DOT_INDENT
    lines = [
        "digraph G {",
        f"{indent}rankdir=LR;",
        f"{indent}node[shape=box];",
        f"{indent}splines=true;",
        f"{indent}nodesep=0.25;",  # Vertical distance between nodes
        f"{indent}ranksep=1;",  # Horizontal distance between nodes
        f"{indent}concentrate=true;",
        "",
    ]
    triples = sorted(convert_digraph_to_triples(g))

    # Add nodes.
    if not group_by_node_type:
        for s, _, o in triples:
            for v in (s, o):
                label = node_labels.get(v) if node_labels else v
                if label:
                    line = f'{indent}"{_get_dot_safe_string(v)}" [label="{label}"];'
                    if line not in lines:
                        lines.append(line)
    else:
        groups = collections.defaultdict(list)
        for s, _, o in triples:
            for v in (s, o):
                t = get_stix2_type_from_id(v)
                groups[t].append(v)

        for t, nodes in groups.items():
            lines.append(f"{indent}subgraph cluster_{_get_dot_safe_string(t)} {{")
            lines.append(f'{indent}{indent}label="{t}";')
            for v in nodes:
                label = node_labels.get(v) if node_labels else v
                if label:
                    line = f'{indent}{indent}"{_get_dot_safe_string(v)}" [label="{label}"];'
                    if line not in lines:
                        lines.append(line)
            lines.append(f"{indent}}}")

    # Add edges.
    for s, p, o in triples:
        if node_labels and not (s in node_labels and o in node_labels):
            continue

        edge_attrs = []

        if include_edge_labels:
            edge_attrs.append(f'label="{p}"')

        color = DEFAULT_COLORS_BY_NODE_TYPE.get(get_stix2_type_from_id(s))
        if color:
            edge_attrs.append(f'color="{color}"')

        s = _get_dot_safe_string(s)
        o = _get_dot_safe_string(o)

        if edge_attrs:
            line = f'{indent}"{s}" -> "{o}" [{", ".join(edge_attrs)}];'
        else:
            line = f'{indent}"{s}" -> "{o}";'
        lines.append(line)

    lines.append("}")
    return "\n".join(lines)


# TODO
def convert_triples_to_dot(triples: Iterable[Triple]) -> str:
    indent = " " * DOT_INDENT
    lines = [
        "digraph G {",
        f"{indent}rankdir=LR;",
        f"{indent}node[shape=box];",
        f"{indent}splines=true;",
        f"{indent}nodesep=0.25;",
        f"{indent}ranksep=1;",
        f"{indent}concentrate=true;",
        "",
    ]
    triples = sorted(triples)
    for triple in triples:
        s, _, o = triple
        for v in (s, o):
            line = f'{indent}"{_get_dot_safe_string(v)}" [label="{v}"];'
            if line not in lines:
                lines.append(line)

    lines.append("")
    for triple in triples:
        s, p, o = triple
        line = f'{indent}"{_get_dot_safe_string(s)}" -> "{_get_dot_safe_string(o)}" [label="{p}"];'
        if line not in lines:
            lines.append(line)

    lines.append("}")
    return "\n".join(lines)


def get_groups(objects: Iterable[dict], group_by: str) -> Dict[str, List[dict]]:
    m = collections.defaultdict(list)
    for o in objects:
        try:
            m[o[group_by]].append(o)
        except KeyError:
            continue
    return dict(m)


def convert_triples_to_digraph(
    triples: Iterable[Triple], predicate_attr: str = "relationship_type"
) -> nx.DiGraph:
    g = nx.DiGraph()

    for triple in triples:
        s, p, o = triple
        edge_data = {predicate_attr: p}
        g.add_edge(s, o, **edge_data)

    return g


def get_node_labels(rows: Iterable[dict], k: str) -> Dict[str, str]:
    m = {}
    for o in rows:
        try:
            m[o["id"]] = o[k]
        except KeyError:
            continue
    return m


def get_stix2_type_from_id(stix2_id: str) -> str:
    return stix2_id.split("--")[0]


def parse_timestamp(t: Optional[str]) -> Optional[datetime.datetime]:
    if t is not None:
        return datetime.datetime.fromisoformat(t)


def get_uuid5(data: dict) -> str:
    namespace = uuid.UUID(UUID_NAMESPACE)
    blob = jcs.canonicalize(data).decode("utf-8")
    return str(uuid.uuid5(namespace, blob))


def get_stix2_data_source(
    data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]]
) -> Union[DataSource, CompositeDataSource]:

    if isinstance(data_sources, str):
        return _get_stix2_data_source(data_sources)
    elif isinstance(data_sources, (MemorySource, DataSource, CompositeDataSource)):
        return data_sources
    else:
        data_sources = [_get_stix2_data_source(ds) for ds in data_sources]
        composite_data_source = CompositeDataSource()
        composite_data_source.add_data_sources(data_sources)
        return composite_data_source


def get_stix2_data_source_with_fallback(
    data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]],
    fallback_data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]],
):
    try:
        return get_stix2_data_source(data_sources)
    except ValueError:
        return get_stix2_data_source(fallback_data_sources)


def _get_stix2_data_source(src: Union[str, DataSource]) -> DataSource:
    if isinstance(src, (MemorySource, DataSource)):
        return src

    if src.startswith(("http://", "https://")):
        return _get_stix2_memory_source_from_web(src)
    else:
        return _get_stix2_memory_source_from_files([src])


def _get_stix2_memory_source_from_files(paths: Iterable[str]) -> MemoryStore:
    paths = set(
        iter_file_paths(
            itertools.chain.from_iterable(
                map(lambda p: glob.glob(get_real_path(p)), paths)
            )
        )
    )
    with concurrent.futures.ThreadPoolExecutor() as executor:
        objects = []
        for src in executor.map(_get_stix2_memory_source_from_file, paths):
            objects.extend(src.query())
        return MemorySource(objects)


def _get_stix2_memory_source_from_file(path: str) -> MemoryStore:
    with open(path, "rb") as file:
        stix_data = json.load(file)
        return MemorySource(stix_data=stix_data)


def _get_stix2_memory_source_from_web(url: str) -> MemoryStore:
    response = requests.get(url, verify=False)
    response.raise_for_status()
    return MemorySource(response.json()["objects"])


def iter_file_paths(paths: Iterable[str]) -> Iterator[str]:
    for path in paths:
        path = get_real_path(path)
        if os.path.isdir(path):
            for directory, _, filenames in os.walk(path):
                for filename in filenames:
                    yield os.path.join(directory, filename)
        elif os.path.exists(path):
            yield path


def get_real_path(path: str) -> str:
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)
    path = os.path.realpath(path)
    return path


def render_dot(dot: str, path: str):
    with tempfile.NamedTemporaryFile(mode="w", delete=True) as file:
        file.write(dot)
        file.flush()
        render_dot_file(file.name, path)


def render_dot_file(input_file: str, output_file: str):
    os.system(f"dot -Tpng {input_file} -Gdpi=300 -o {output_file}")


def get_external_id(o: dict) -> str:
    if is_likely_mitre_attack(o):
        f = get_mitre_attack_external_id
    elif is_likely_nist_sp_800_53(o):
        f = get_nist_sp_800_53_external_id
    elif is_likely_mitre_capec(o):
        f = get_mitre_capec_external_id
    elif is_likely_mitre_mbc(o):
        f = get_mitre_mbc_external_id
    else:
        raise ValueError(f"Unknown external ID for {o['id']}")
    return f(o)


def get_nist_sp_800_53_external_id(o: dict) -> str:
    for external_id in o.get("external_references", []):
        if external_id["source_name"] in [
            "NIST 800-53 Revision 4",
            "NIST 800-53 Revision 5",
        ]:
            return external_id["external_id"]
    raise ValueError("NIST SP 800-53 external ID not found")


def get_mitre_attack_external_id(o: dict) -> str:
    if o["type"] != "x-mitre-matrix":
        for external_id in o.get("external_references", []):
            if external_id["source_name"] == "mitre-attack":
                return external_id["external_id"]
    raise ValueError("MITRE ATT&CK external ID not found")


def get_mitre_capec_external_id(o: dict) -> str:
    for external_id in o.get("external_references", []):
        if external_id["source_name"] == "capec":
            return external_id["external_id"]
    raise ValueError("MITRE CAPEC external ID not found")


def get_mitre_mbc_external_id(o: dict) -> str:
    try:
        return o["obj_defn"]["external_id"]
    except KeyError:
        for ext in o["extensions"].values():
            o = ext["obj_defn"]
            if o["source_name"] == "mitre-mbc":
                return o["external_id"]
    raise ValueError("MITRE MBC external ID not found")


def is_likely_mitre_attack(o: dict) -> bool:
    return (
        is_likely_mitre_attack_enterprise(o)
        or is_likely_mitre_attack_mobile(o)
        or is_likely_mitre_attack_ics(o)
    )


def is_likely_mitre_attack_enterprise(o: dict) -> bool:
    found = o.get("x_mitre_domains")
    if found and "enterprise-attack" in found:
        return True
    return False


def is_likely_mitre_attack_mobile(o: dict) -> bool:
    found = o.get("x_mitre_domains")
    if found and "mobile-attack" in found:
        return True
    return False


def is_likely_mitre_attack_ics(o: dict) -> bool:
    found = o.get("x_mitre_domains")
    if found and "ics-attack" in found:
        return True
    return False


def is_likely_nist_sp_800_53(o: dict) -> bool:
    try:
        _ = get_nist_sp_800_53_external_id(o)
    except ValueError:
        return False
    else:
        return True


def is_likely_mitre_capec(o: dict) -> bool:
    return "x_capec_version" in o


def is_likely_mitre_mbc(o: dict) -> bool:
    def a() -> bool:
        try:
            return o["obj_defn"]["source_name"] == "mitre-mbc"
        except KeyError:
            return False

    def b() -> bool:
        try:
            for ext in o["extensions"].values():
                if ext["obj_defn"]["source_name"] == "mitre-mbc":
                    return True
        except KeyError:
            return False

    return a() or b()


def is_likely_cve(o: dict) -> bool:
    if get_stix2_type_from_id(o["id"]) == "vulnerability":
        for ext in o["external_references"]:
            if ext["source_name"] == "cve":
                return True
    return False
