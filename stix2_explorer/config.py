from dataclasses import dataclass
import dataclasses
from typing import Iterable, Optional
from stix2_explorer.constants import BLACK, DATA_SOURCE_URLS


DEFAULT_NODE_COLOUR = BLACK
DEFAULT_EDGE_COLOUR = BLACK

DIRECTED_BY_DEFAULT = True
REPLACE_BY_DEFAULT = False


@dataclass()
class DataSource:
    name: str
    url: Optional[str]
    path: Optional[str]
    enabled: bool = True


@dataclass()
class NodePolicy:
    type: Optional[str] = "*"


@dataclass()
class NodeColouringPolicy(NodePolicy):
    colour: str = DEFAULT_NODE_COLOUR


@dataclass()
class EdgePolicy:
    subject: Optional[str] = "*"
    predicate: Optional[str] = "*"
    object: Optional[str] = "*"


@dataclass()
class EdgeColouringPolicy(EdgePolicy):
    colour: str = DEFAULT_EDGE_COLOUR


@dataclass()
class EdgeLabellingPolicy:
    directed: bool = DIRECTED_BY_DEFAULT
    replace: bool = REPLACE_BY_DEFAULT
    

@dataclass()
class Config:
    data_sources: Optional[Iterable[DataSource]] = dataclasses.field(default_factory=list)
    node_colours: Optional[Iterable[NodeColouringPolicy]] = dataclasses.field(default_factory=list)
    edge_colours: Optional[Iterable[EdgeColouringPolicy]] = dataclasses.field(default_factory=list)
    edge_labels: Optional[Iterable[EdgeLabellingPolicy]] = dataclasses.field(default_factory=list)


def generate_config() -> Config:
    data_sources = get_default_data_sources()
    return Config(data_sources=data_sources)


def get_default_data_sources() -> Iterable[DataSource]:
    data_sources = []
    for name, url in DATA_SOURCE_URLS.items():
        data_source = DataSource(
            name=name,
            url=url,
            enabled=True,
        )
        data_sources.append(data_source)
    return data_sources


def parse_config(data: dict) -> Config:
    data_sources = []
    for o in data.get('data_sources', []):
        data_sources.append(DataSource(**o))
    
    if not data_sources:
        data_sources = get_default_data_sources()
    
    node_colours = []
    for o in data.get('node_colours', []):
        node_colours.append(NodeColouringPolicy(**o))
    
    edge_colours = []
    for o in data.get('edge_colours', []):
        edge_colours.append(EdgeColouringPolicy(**o))
    
    edge_labels = []
    for o in data.get('edge_labels', []):
        edge_labels.append(EdgeLabellingPolicy(**o))

    return Config(
        data_sources=data_sources,
        node_colours=node_colours,
        edge_colours=edge_colours,
        edge_labels=edge_labels,
    )
