import collections
from dataclasses import dataclass
import sys
from typing import Any, Callable, List, Optional, Set, Tuple
import networkx as nx

import polars as pl
from stix2.serialization import STIXJSONEncoder as _JSONEncoder
from stix2.base import _STIXBase
from stix2.utils import STIXdatetime
import json
from typing import Any, Dict, Iterable, Iterator, Union
import networkx as nx
from stix2.datastore import DataSource
import re
from typing import Iterable
import os
import requests
from stix2 import (
    FileSystemSource,
    MemoryStore,
    MemorySource,
    CompositeDataSource,
)
import stix2
from typing import Iterable, Union
from stix2.serialization import STIXJSONEncoder as _JSONEncoder
from stix2.base import _STIXBase
from urllib.parse import urlparse

from stix2_explorer.constants import DEFAULT_COLORS_BY_TYPE, UUID_NAMESPACE
from stix2_explorer.decoders import Decoder, GenericDecoder, MitreDecoder

import logging

logger = logging.getLogger(__name__)


DOT_INDENT = 4

class JSONEncoder(_JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, _STIXBase):
            return dict(o)
        elif isinstance(o, STIXdatetime):
            return o.isoformat()
        elif isinstance(o, set):
            return list(o)
        elif iter(o) == o:
            return list(o)
        else:
            return super().default(o)


def convert_stix2_objects_to_digraph(
    objects: Iterable[Any],
    decoders: Optional[Iterable[Decoder]] = None,
    ignore_deprecated: bool = True,
    ignore_revoked: bool = True,
    drop_dangling_references: bool = True,
) -> nx.DiGraph:

    if not decoders:
        decoders = [GenericDecoder(), MitreDecoder()]

    g = nx.DiGraph()
    objects = list(convert_stix2_objects_to_dicts(
        filter_stix2_objects(
            objects,
            include_deprecated=ignore_deprecated,
            include_revoked=ignore_revoked,
        )
    ))

    # Decoders can be stacked - this allows us to see exactly what different decoders are doing.
    for decoder in decoders:
        for node in decoder.iter_nodes(objects):
            data = node.data or {}
            if 'type' not in data:
                data['type'] = node.type
            #g.add_node(node.id, **data)
            g.add_node(node.id)

        for (s, p, o, d) in decoder.iter_edges(objects):
            d = d or {}
            d['label'] = p
            g.add_edge(s, o, **d)
    
    # Dangling references are references to objects outside of the graph.
    if drop_dangling_references:
        object_ids = {o["id"] for o in objects}
        referenced_object_ids = set(g.nodes)
        dangling_references = referenced_object_ids - object_ids

        if dangling_references:
            logger.info(f"Dropping {len(dangling_references)} dangling references")
            g.remove_nodes_from(dangling_references)

    return g


def convert_stix2_objects_to_triples(
    objects: Iterable[Any],
    decoders: Optional[Iterable[Decoder]] = None,
    ignore_deprecated: bool = True,
    ignore_revoked: bool = True,
) -> nx.DiGraph:
    """
    Given a stream of STIX 2 objects, return a stream of triples.
    """
    g = convert_stix2_objects_to_digraph(
        objects,
        decoders=decoders,
        ignore_deprecated=ignore_deprecated,
        ignore_revoked=ignore_revoked,
    )
    return convert_digraph_to_triples(g)


def convert_stix2_objects_to_triple_dataframe(
    objects: Iterable[Any],
    decoders: Optional[Iterable[Decoder]] = None,
    ignore_deprecated: bool = True,
    ignore_revoked: bool = True,
    drop_isolates: bool = True,
    drop_dangling_references: bool = True,
) -> pl.DataFrame:
    
    g = convert_stix2_objects_to_digraph(
        objects,
        decoders=decoders,
        ignore_deprecated=ignore_deprecated,
        ignore_revoked=ignore_revoked,
        drop_dangling_references=drop_dangling_references,
        drop_isolates=drop_isolates,
    )

    rows = []
    for s, p, o in sorted(convert_digraph_to_triples(g)):
        row = {
            'subject': s,
            'predicate': p,
            'object': o,
        }
        rows.append(row)
    return pl.DataFrame(rows)


def convert_stix2_objects_to_dicts(rows: Iterable[Any]) -> Iterator[dict]:
    for row in rows:
        if isinstance(row, dict):
            yield row
        else:
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


def iter_stix2_objects(
        data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]],
        decoders: Optional[Iterable[Decoder]] = None,
        ignore_deprecated: bool = True,
        ignore_revoked: bool = True) -> Iterator[Any]:

    src = get_data_source(data_sources)
    rows = src.query()

    rows = convert_stix2_objects_to_dicts(rows)

    if ignore_deprecated or ignore_revoked:
        rows = filter_stix2_objects(
            rows,
            decoders=decoders,
            include_deprecated=ignore_deprecated,
            include_revoked=ignore_revoked,
        )
    yield from rows


def filter_stix2_objects(
    objects: Iterable[Any],
    object_ids: Optional[Iterable[str]] = None,
    object_types: Optional[Iterable[str]] = None,
    decoders: Optional[Iterable[Decoder]] = None,
    include_deprecated: bool = True,
    include_revoked: bool = True,
) -> Iterator[Any]:

    decoders = decoders or [GenericDecoder(), MitreDecoder()]

    if not include_deprecated:
        objects = filter(lambda o: not any(decoder.is_deprecated(o) for decoder in decoders), objects)

    if not include_revoked:
        objects = filter(lambda o: not any(decoder.is_revoked(o) for decoder in decoders), objects)

    if object_ids:
        object_ids = set(object_ids)
        objects = filter(lambda o: o["id"] in object_ids, objects)

    if object_types:
        object_types = set(object_types)
        objects = filter(lambda o: get_stix2_type_from_id(o["id"]) in object_types, objects)

    yield from objects


def drop_dangling_references(objects: Iterable[Any], decoders: Optional[Iterable[Decoder]] = None) -> List[dict]:
    objects = list(convert_stix2_objects_to_dicts(objects))
    dangling_references = get_dangling_references(
        objects,
        decoders=decoders,
    )
    if dangling_references:
        logger.debug(f"Dropping {len(dangling_references)} dangling reference(s): {sorted(dangling_references)}")
        objects = list(filter(lambda o: o["id"] not in dangling_references, objects))
    return objects


def get_dangling_references(
        objects: Iterable[Any],
        decoders: Optional[Iterable[Decoder]] = None) -> Set[str]:
    
    objects = list(objects)
    object_ids = {o["id"] for o in objects}
    
    triples = convert_stix2_objects_to_triples(
        objects,
        decoders=decoders,
    )
    referenced_object_ids = {s for s, _, _ in triples} | {o for _, _, o in triples}
    return referenced_object_ids - object_ids


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
    

def get_data_source_with_fallback(
        data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]],
        fallback_data_sources: Union[str, DataSource, Iterable[Union[str, DataSource]]]):
    try:
        return get_data_source(data_sources)
    except ValueError:
        return get_data_source(fallback_data_sources)


def _get_data_source(src: Union[str, DataSource]) -> DataSource:
    if isinstance(src, DataSource):
        return src
    
    if src.startswith(("http://", "https://")):
        return _get_memory_source_from_web(src)
    
    src = get_real_path(src)
    if os.path.exists(src):
        if os.path.isdir(src):
            return FileSystemSource(src)
        else:
            return _get_memory_source_from_file(src)
    else:
        real_path = get_real_path(src)
        if os.path.exists(real_path):
            return _get_data_source(real_path)
        
        raise ValueError(f"Invalid path: {src}")


def _get_memory_source_from_file(path: str) -> MemoryStore:
    with open(path, "rb") as file:
        stix_data = json.load(file)
        return MemorySource(stix_data=stix_data)


def _get_memory_source_from_web(url: str) -> MemoryStore:
    response = requests.get(url, verify=False)
    response.raise_for_status()
    return MemorySource(response.json()["objects"])


def get_real_path(path: str) -> str:
    path = os.path.expanduser(path)
    path = os.path.expandvars(path)
    path = os.path.realpath(path)
    return path



def get_stix2_type_from_id(stix2_id: str) -> str:
    return stix2_id.split('--')[0]


def convert_digraph_to_dot(
        g: nx.DiGraph, 
        group_by: Optional[str] = None, 
        indent: int = DOT_INDENT) -> str:
    
    objects = [o[1] for o in g.nodes(data=True)]

    indent = max(indent, 1)
    lines = [
        'digraph G {',
        f'{" " * indent}rankdir=LR;',
        f'{" " * indent}node [shape=box];',
        f'{" " * indent}splines=true;',
        f'{" " * indent}nodesep=0.15;',
        f'{" " * indent}ranksep=0.15;',
    ]

    # Add nodes
    if not group_by:
        for o in objects:
            object_id = _get_dot_safe_string(o['id'])
            lines.append(f'{" " * indent}{object_id}')
    else:
        objects = [o[1] for o in g.nodes(data=True)]
        groups = get_groups(objects, group_by)
        for group_label, members in groups.items():
            safe_group_label = _get_dot_safe_string(group_label)

            lines.append(f'{" " * indent}subgraph cluster_{safe_group_label} {{')
            lines.append(f'{" " * indent * 2}label="{group_label}";')

            for o in members:
                v = _get_dot_safe_string(o['id'])
                #lines.append(f'{" " * indent * 2}{v} [label=\"{o["name"]}\"];')
                lines.append(f'{" " * indent * 2}{v}')

            lines.append(f'{" " * indent}}}')
    
    # Add edges
    for s, o, d in g.edges(data=True):
        p = d['label']
        edge_color = DEFAULT_COLORS_BY_TYPE[get_stix2_type_from_id(s)]

        s, p, o = map(_get_dot_safe_string, (s, p, o))

        #lines.append(f'{" " * indent}"{s}" -> "{o}" [label=\"{p}\" color=\"{edge_color}\"];')
        lines.append(f'{" " * indent}"{s}" -> "{o}" [color=\"{edge_color}\"];')

    lines.append('}')
    return '\n'.join(lines)


def _get_dot_safe_string(s: str) -> str:
    return re.sub(r'[\W-]+', '_', s)


def convert_triples_to_dot(triples: Iterable[Tuple[str, str, str]], group_by: Optional[str] = None, indent: int = DOT_INDENT) -> str:
    g = convert_triples_to_digraph(triples)
    return convert_digraph_to_dot(g=g, group_by=group_by, indent=indent)


def get_groups(objects: Iterable[dict], key: str) -> Dict[str, List[dict]]:
    m = collections.defaultdict(list)
    for o in objects:
        m[o[key]].append(o)
    return dict(m)


### Graphs

def convert_digraph_to_triples(
        g: nx.DiGraph, 
        directed: bool = True) -> Iterable[Tuple[str, str, str]]:
    
    seen = set()
    for a, b, data in g.edges(data=True):
        label = data["label"]

        triple = (a, label, b)
        if triple not in seen:
            seen.add(triple)
            if not directed:
                seen.add(reversed(triple))
            
            yield triple


def convert_triples_to_digraph(triples: Iterable[Tuple[str, str, str]]) -> nx.DiGraph:
    g = nx.DiGraph()
    for s, p, o in triples:
        g.add_edge(s, o, label=p)
    return g


def convert_digraph_to_undirected_graph(g: nx.DiGraph) -> nx.Graph:
    return g.to_undirected()


def convert_triples_to_undirected_graph(triples: Iterable[Tuple[str, str, str]]) -> nx.Graph:
    g = convert_triples_to_digraph(triples)
    return convert_digraph_to_undirected_graph(g)


def tally_edges_by_type(g: nx.DiGraph) -> pl.DataFrame:
    m = collections.defaultdict(int)
    for (s, p, o) in convert_digraph_to_triples(g):
        s = get_stix2_type_from_id(s)
        o = get_stix2_type_from_id(o)
        e = (s, p, o)
        m[e] += 1
    
    rows = []
    for (s, p, o), total in m.items():
        row = {
            'subject': s,
            'predicate': p,
            'object': o,
            'total': total,
        }
        rows.append(row)

    df = pl.DataFrame(rows)
    df = df.sort('total', descending=True)
    return df
    

def relabel_nodes(g: nx.DiGraph, f: Callable[[], str]) -> nx.DiGraph:
    m = {}
    for u in g.nodes:
        try:
            v = f(u)
            if v is None:
                continue
        except Exception:
            continue
        else:
            m[u] = v
    return nx.relabel_nodes(g, m)


def relabel_nodes_by_external_id(g: nx.DiGraph) -> nx.DiGraph:
    return relabel_nodes(g, lambda u: parse_attack_external_id(g.nodes[u]))


def parse_attack_external_id(o: dict) -> Optional[str]:
    for ref in o.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id')
