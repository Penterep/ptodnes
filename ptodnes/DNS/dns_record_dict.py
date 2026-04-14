from typing import Generator, List, Self

from ptodnes.DNS.dnsinfo import DNSInfo
from ptodnes.DNS.record import DNSRecord
from ptodnes.datasources.datasource import Datasource, DatasourceObject


class DNSRecordDict(dict[str, DNSInfo]):
    """
    DNS Records dictionary
    """
    def append(self, item: DatasourceObject):
        """
        Add DNS record to dictionary. Checks if record exists.
        :param item: DNS record
        :return:
        """
        if item not in self.keys():
            self[item.domain] = DNSInfo(domain=item.domain, records=list(set(item.DNSData)))
        else:
            for obj in item.DNSData:
                if obj not in self[item.domain].records:
                    self[item.domain].records.append(obj)
                else:
                    for i in range(len(self[item.domain].records)):
                        if self[item.domain].records[i] == obj:
                            self[item.domain].records[i].source.update(obj.source)
    def get_records(self, domain: str) -> list[DNSRecord] | None:
        """
        Get DNS records for a domain
        :param domain: domain to get records for
        :return: list of DNS records or None if domain not found
        """
        dns_info = self.get(domain, None)
        if dns_info is None:
            return []
        return dns_info.records
    
    def is_vhost(self, domain: str) -> bool:
        """
        Check if domain is a vhost
        :param domain: domain to check
        :return: True if domain is a vhost, False otherwise
        """
        dns_info = self.get(domain, None)
        if dns_info is None:
            return False
        return dns_info.is_vhost
    
    def set_vhost_info(self, domain: str, is_vhost: bool, vhost_hits: list[str] | None):
        """
        Set vhost information for a domain
        :param domain: domain to set vhost information for
        :param is_vhost: True if domain is a vhost, False otherwise
        :param vhost_hits: list of vhost hits or None if no hits
        :return:
        """
        dns_info = self.get(domain, None)
        if dns_info is None:
            self[domain] = DNSInfo(is_vhost=is_vhost, vhost_hits=vhost_hits, records=[])
        else:
            dns_info.is_vhost = is_vhost
            dns_info.vhost_hits = vhost_hits
        

    def extend(self, items: list[DatasourceObject]):
        """
        Add DNS records to dictionary
        :param items: DNS Records
        :return:
        """
        for item in items:
            self.append(item)

    def by_ip(self, ip: str) -> Self:
        record = DNSRecord(record_last_seen=None, type='A', value=ip, verified=False, source={''}, ttl=0)
        new = DNSRecordDict()
        for domain,values in self.items():
            if record not in values:
                continue
            for value in values.records:
                if value.type == 'A' and value.value == ip:
                    new[domain] = values
                    break
        return new
            
    def by_datasource(self, datasource: Datasource) -> Self:
        datasource_name = datasource.__class__.__name__
        new = DNSRecordDict()
        for domain,values in self.items():
            for value in values.records:
                if datasource_name in value.source:
                    new[domain] = values
                    break
        return new
            
            
                    
        
    def filter(self, types: list):
        """
        Filter DNS records by type
        :param types: types to filter
        :return:
        """
        keys = []
        filter_types = types.copy()
        if 'ANY' in filter_types:
            return
        self.filterNX()
        for key, value in self.items():
            filtered = [x for x in filter((lambda i: i.type in filter_types), value.records)]
            if not filtered:
                keys.append(key)
            self[key].records = filtered
        for key in keys:
            del (self[key])

    def filter_untrusted(self):
        """
        Filter records that have not been verified
        :return:
        """
        keys = []
        for key, value in self.items():
            filtered = [x for x in filter((lambda i: i.verified), value.records)]
            if not filtered:
                keys.append(key)
            self[key].records = filtered
        for key in keys:
            del (self[key])


    def filterNX(self):
        """
        Filter out domains without any record
        :return:
        """
        keys = []
        for key, value in self.items():

            while DNSRecord('<NONE>',0,'<EMPTY>',False, {''}, None) in value.records:
                value.records.remove(DNSRecord('<NONE>',0,'<EMPTY>',False, {''}, None))
            if not value.records:
                keys.append(key)

        for key in keys:
            del(self[key])

    def seq(self) -> Generator[DatasourceObject]:
        for key in self.keys():
            do = DatasourceObject(domain=key, DNSData=self[key])
            yield do

    def as_list(self) -> List[DatasourceObject]:
        return list(self.seq())