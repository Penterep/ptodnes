from typing import overload

import aiohttp
import asyncio
from ptodnes.datasources.datasource import Datasource, DatasourceObject, date_from_iso, DNSRecordGenerator

class Shodan(Datasource):
    _api_url: str = "https://api.shodan.io/dns/domain/{domain}?key={api_key}"
    _ips_url: str = "https://api.shodan.io/shodan/host/{IP}?key={api_key}"

    def __init__(self, api_key: str = ''):
        super().__init__()
        self.__api_keys = self.config.get('api_keys', [])
        self._enabled = self.config.get('enabled', True)
        if not self.__api_keys:
            self._api_key = api_key
        if type(self.__api_keys) is not type([]):
            self._api_key = api_key
        else:
            try:
                self._api_key = self.__api_keys.pop(0)
            except IndexError:
                self._api_key = api_key

    def add_api_key(self, api_key: str):
        self.__api_keys.append(api_key)
        if not self._api_key:
            self._api_key = api_key

    async def check_api_key(self):
        if not self._api_key:
            self.print_error("Missing, disabling module")
            self._enabled = False
            return
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {"accept": "application/json"}
        retry = self._retry
        while retry > 0:
            try:
                async with (aiohttp.ClientSession(timeout=timeout) as session):
                    async with session.get(f'https://api.shodan.io/api-info?key={self._api_key}', headers=headers
                                           ) as response:
                        if response.status != 200:
                            self.print_error("Invalid, disabling module")
                            self._enabled = False
                        else:
                            self.print_ok("Present")
                break
            except TimeoutError:
                await asyncio.sleep(2)
                retry -= 1

    async def search(self, domain: str):
        """
        Search for `resource` information for `domain` in Shodan.

        :param domain: The domain to search for.
        :return: `DatasourceObject` object if domain is found, None otherwise
        """

        if not self._enabled:
            return []
        self.print_info(f"Started search for domain {domain}")
        for i in range(self.retry):
            try:
                domain_list = []
                next_url = self._api_url.format(domain=domain, api_key=self._api_key)
                headers = {"accept": "application/json"}
                datasource_objects = []
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(next_url, headers=headers) as response:
                        if response.status != 200:
                            return datasource_objects
                        data = await response.json()
                        domain_data = data.get('data', {})
                        got_domain = data.get('domain', domain)
                        more_data = data.get('more', False)
                        subdomains = {}
                        for record in domain_data:
                            subdomain = record.get('subdomain', '')
                            if not subdomain:
                                subdomain = got_domain
                            else:
                                subdomain = f"{subdomain}.{got_domain}"
                            record_list = subdomains.get(subdomain, [])
                            modified_record = {
                                "type": record.get('type', ''),
                                "value": record.get('value', ''),
                                "ttl": record.get('ttl', -1),
                                "record_last_seen": date_from_iso(record.get('last_seen', None)),
                            }
                            record_list.append(modified_record)
                            subdomains[subdomain] = record_list
                        for subdomain, subdomain_data in subdomains.items():
                            self.print_ok(f"Found subdomain {subdomain}", clear_to_eol=True, end='\r')
                            datasource_object = DatasourceObject(domain=subdomain,
                                                                 DNSData=[DNSRecordGenerator(
                                                                     verified=False, source=__class__.__name__, **x)
                                                                          for x in subdomain_data])
                            domain_list.append(subdomain)
                            datasource_objects.append(datasource_object)
                        if more_data:
                            self.print_warning(f"More results available for {domain}. \
Current API level does not support more results.")
                if domain not in domain_list:
                    domain_list.append(domain)
                # return list(set(domain_list))
                self.print_info(f"Finished search for domain {domain}")
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"{domain} lookup canceled.")
            except TimeoutError:
                self.print_warning(f"Timed out when fetching data for {domain}. Trying again. ({i + 1}/{self.retry})")
                await asyncio.sleep(2)
        self.print_error(f"Max timeout reached for {domain}. SKIPPING.")
        return []

    async def reverse_search(self, IP: str):
        if not self._enabled:
            return []
        if self._barier:
            self.print_info(f"Started search for IP {self.scandidate}")
            self._barier = False
        for i in range(self.retry):
            try:
                domain_list = []
                next_url = self._ips_url.format(IP=IP, api_key=self._api_key)
                headers = {"accept": "application/json"}
                datasource_objects = []
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(next_url, headers=headers) as response:
                        if response.status != 200:
                            return datasource_objects
                        data = await response.json()
                        domain_data = data.get('hostnames', [])
                        for record in domain_data:
                            datasource_object = DatasourceObject(domain=record,
                                                                 DNSData=[DNSRecordGenerator(verified=False,
                                                                                             source=__class__.__name__,
                                                                                             value=IP,
                                                                                             type="A",
                                                                                             ttl=None,
                                                                                             record_last_seen=None)])
                            domain_list.append(record)
                            datasource_objects.append(datasource_object)
                # return list(set(domain_list))
                if self._end_barier:
                    self.print_info(f"Finished search for IP {self.scandidate}")
                    self._end_barier = False
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"IP {self.scandidate} lookup canceled.")
            except TimeoutError:
                self.print_warning(f"Timed out when fetching data for IP {self.scandidate}. Trying again. ({i + 1}/{self.retry})")
                await asyncio.sleep(2)
        self.print_error(f"Max timeout reached for IP {self.scandidate}. SKIPPING.")
        return []