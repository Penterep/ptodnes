import aiohttp
import asyncio
from ptodnes.datasources.datasource import Datasource, DatasourceObject, DNSRecordGenerator, date_from_utc


class VirusTotal(Datasource):
    _api_key: str = ""
    _api_url: str = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    _ips_url: str = "https://www.virustotal.com/api/v3/ip_addresses/{IP}/resolutions?limit=40"
    def __init__(self, api_key: str = ''):
        super().__init__()
        self.__api_keys_list = self.config.get('api_keys', [])
        self._enabled = self.config.get('enabled', True)
        if not self.__api_keys_list:
            self._api_key = api_key
        if type(self.__api_keys_list) is not type(list):
            self._api_key = api_key
        self.__api_keys = iter(self.__api_keys_list)
        try:
            self._api_key = next(self.__api_keys)
        except StopIteration:
            self._api_key = api_key

    def add_api_key(self, api_key: str):
        print("Adding API key to VirusTotal")
        self.__api_keys_list.append(api_key)
    
    async def check_api_key(self):
        if not self._api_key:
            self.print_error("Missing, disabling module")
            self._enabled = False
            return
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {"accept": "application/json", "x-apikey": self._api_key}
        retry = self._retry
        while retry > 0:
            try:
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get('https://www.virustotal.com/api/v3/domains/example.com', headers=headers) as response:
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
        Search for `resource` information for `domain` in VirusTotal.

        :param domain: The domain to search for.
        :param resource: The resource to search for. Valid resources are: `comments`, `whois`, `subdomains`, `resolutions`, `detected_urls`.
        :return: DomainInfo object if domain is found, None otherwise
        """

        if not self._enabled:
            return []
        datasource_objects = []
        self.print_info(f"Started search for domain {domain}")
        for i in range(self.retry):
            try:
                domain_list = []
                next_url = self._api_url.format(domain=domain)
                headers = {"accept": "application/json", "x-apikey": self._api_key}
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    while next_url is not None:
                        async with session.get(next_url, headers=headers) as response:
                            if response.status != 200:
                                self.print_error(
                                    (await response.json()).get('error', {}).get('message', "Unspecified error."))
                                if response.status == 429:
                                    self._api_key = next(self.__api_keys)
                                    headers = {"accept": "application/json", "x-apikey": self._api_key}
                                    continue
                                return domain_list
                            data = await response.json()
                            try:
                                domain_data = data.get('data', [])
                                for record in domain_data:
                                    subdomain = record.get('id', '')
                                    self.print_ok(f"Found subdomain {subdomain}")
                                    datasource_object = DatasourceObject(domain=subdomain, DNSData=[DNSRecordGenerator(**x,source=__class__.__name__, record_last_seen=date_from_utc(record.get('attributes',{}).get('last_dns_records_date',None))) for x in record.get('attributes',{}).get('last_dns_records',[])])
                                    domain_list.append(subdomain)
                                    datasource_objects.append(datasource_object)
                                next_url = data.get('links',{}).get('next', None)
                            except Exception as e:
                                self.print_error(f"Unspecified error: {e}")
                                next_url = None
                if domain not in domain_list:
                    domain_list.append(domain)
                #return list(set(domain_list))
                self.print_info(f"Finished search for domain {domain}")
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"{domain} lookup canceled.")
                return datasource_objects
            except StopIteration:
                self.print_error(f"Could not get more records from VirusTotal API.")
                return datasource_objects
            except TimeoutError:
                self.print_warning(f"Timed out when fetching data for {domain}. Trying again. ({i + 1}/{self.retry})")
                await asyncio.sleep(2)
        self.print_error(f"Max timeout reached for {domain}. SKIPPING.")
        return []

    async def reverse_search(self, IP: str):
        if not self._enabled:
            return []
        datasource_objects = []
        self.print_info(f"Started search for IP {IP}")
        for i in range(self.retry):
            try:
                domain_list = []
                next_url = self._ips_url.format(IP=IP)
                headers = {"accept": "application/json", "x-apikey": self._api_key}
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    while next_url is not None:
                        async with session.get(next_url, headers=headers) as response:
                            if response.status != 200:
                                self.print_error(
                                    (await response.json()).get('error', {}).get('message', "Unspecified error."))
                                if response.status == 429:
                                    self._api_key = next(self.__api_keys)
                                    headers = {"accept": "application/json", "x-apikey": self._api_key}
                                    continue
                                return domain_list
                            data = await response.json()
                            try:
                                domain_data = data.get('data', [])
                                for record in domain_data:
                                    subdomain = record.get('attributes', {}).get('host_name', '')
                                    self.print_ok(f"Found subdomain {subdomain}")
                                    datasource_object = DatasourceObject(domain=subdomain, DNSData=[DNSRecordGenerator(type="A",source=__class__.__name__,ttl=None,value=IP, record_last_seen=date_from_utc(record.get('attributes',{}).get('date',None)))])
                                    domain_list.append(subdomain)
                                    datasource_objects.append(datasource_object)
                                next_url = data.get('links',{}).get('next', None)
                            except Exception as e:
                                self.print_error(f"Unspecified error: {e}")
                                next_url = None
                #return list(set(domain_list))
                self.print_info(f"Finished search for IP {IP}")
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"{IP} lookup canceled.")
                return datasource_objects
            except StopIteration:
                self.print_error(f"Could not get more records from VirusTotal API.")
                return datasource_objects
            except TimeoutError:
                self.print_warning(f"Timed out when fetching data for IP {IP}. Trying again. ({i + 1}/{self.retry})")
                await asyncio.sleep(2)
        self.print_error(f"Max timeout reached for IP {IP}. SKIPPING.")
        return []