
from dataclasses import dataclass

from ptodnes.DNS.record import DNSRecord


@dataclass
class DNSInfo:
    """
    Class for DNS information about a domain
    """
    domain: str
    is_vhost: bool = False
    matches: bool | None = None
    vhost_hits: list | None = None
    records: list[DNSRecord] | None = None

    def __iter__(self):
        return iter(self.records)
    
    def append(self, record: DNSRecord):
        """
        Append DNS record to DNSInfo
        :param record: DNSRecord to append
        :return:
        """
        self.records.append(record)

    def extend(self, records: list[DNSRecord]):
        """
        Extend DNSInfo with list of DNS records
        :param records: list of DNSRecord to extend with
        :return:
        """
        self.records.extend(records)
    
    def __contains__(self, item):
        return item in self.records
    
    def __len__(self):
        return len(self.records)
    
    def __getitem__(self, index):
        return self.records[index]
    
        