from typing import Generator, List

from ptodnes.DNS.record import DNSRecord
from ptodnes.datasources.datasource import DatasourceObject


class DNSRecordDict(dict[str, list[DNSRecord]]):
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
            self[item.domain] = list(set(item.DNSData))
        else:
            for obj in item.DNSData:
                if obj not in self[item.domain]:
                    self[item.domain].append(obj)
                else:
                    for i in range(len(self[item.domain])):
                        if self[item.domain][i] == obj:
                            self[item.domain][i].source.update(obj.source)

    def extend(self, items: list[DatasourceObject]):
        """
        Add DNS records to dictionary
        :param items: DNS Records
        :return:
        """
        for item in items:
            self.append(item)
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
            filtered = [x for x in filter((lambda i: i.type in filter_types), value)]
            if not filtered:
                keys.append(key)
            self[key] = filtered
        for key in keys:
            del (self[key])

    def filter_untrusted(self):
        """
        Filter records that have not been verified
        :return:
        """
        keys = []
        for key, value in self.items():
            filtered = [x for x in filter((lambda i: i.verified), value)]
            if not filtered:
                keys.append(key)
            self[key] = filtered
        for key in keys:
            del (self[key])


    def filterNX(self):
        """
        Filter out domains without any record
        :return:
        """
        keys = []
        for key, value in self.items():

            while DNSRecord('<NONE>',0,'<EMPTY>',False, {''}, None) in value:
                value.remove(DNSRecord('<NONE>',0,'<EMPTY>',False, {''}, None))
            if not value:
                keys.append(key)

        for key in keys:
            del(self[key])

    def seq(self) -> Generator[DatasourceObject]:
        for key in self.keys():
            do = DatasourceObject(domain=key, DNSData=self[key])
            yield do

    def as_list(self) -> List[DatasourceObject]:
        return list(self.seq())