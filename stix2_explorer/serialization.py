from dataclasses import dataclass
from typing import Any

from stix2.serialization import STIXJSONEncoder as _JSONEncoder
from stix2.base import _STIXBase
from stix2.utils import STIXdatetime
from typing import Any


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