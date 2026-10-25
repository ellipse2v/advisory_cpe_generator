from .cisco import CiscoAdapter
from .paloalto import PaloAltoAdapter
from .stormshield import StormshieldAdapter

ADAPTERS = {a.vendor: a for a in (StormshieldAdapter, CiscoAdapter, PaloAltoAdapter)}
