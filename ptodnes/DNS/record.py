from dataclasses import dataclass
from datetime import datetime


@dataclass
class DNSRecord:
    """
    Base class for DNS record
    """
    type: str
    ttl: int
    value: str
    verified: bool
    source: set[str]
    record_last_seen: datetime | None

    @staticmethod
    def dict_factory(x):
        exclude_fields = ("ttl",)
        return {k: (v.isoformat() if isinstance(v, datetime) else list(v) if isinstance(v, set) else v) for (k, v) in x if ((v is not None) and (k not in exclude_fields))}

    def __eq__(self, other):
        return self.type == other.type and self.value == other.value

    def __hash__(self):
        return hash((self.type, self.value))

@dataclass
class SOARecord(DNSRecord):
    """
    Class for SOA record
    """
    rname: str = None
    retry: int = None
    minimum: int = None
    refresh: int = None
    expire: int = None
    serial: int = None

    def __eq__(self, other):
        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()

@dataclass
class MXRecord(DNSRecord):
    """
    Class for MX record
    """
    priority: int = 0

    def __eq__(self, other):
        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()

@dataclass
class CAARecord(DNSRecord):
    """
    Class for CAA record
    """
    flag: int = None
    tag: str = None

    def __eq__(self, other):
        return super().__eq__(other)

    def __hash__(self):
        return super().__hash__()
