import aiohttp
import asyncio
from ptodnes.datasources.datasource import Datasource, DatasourceObject, DNSRecordGenerator, date_from_utc


class VirusTotal(Datasource):
    _api_key: str = ""
    _api_url: str = "https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    _ips_url: str = "https://www.virustotal.com/api/v3/ip_addresses/{IP}/resolutions?limit=40"
    def __init__(self, api_key: str = ''):
        super().__init__()
        self._enabled = self.config.get('enabled', True)
        self._load_api_keys(api_key)
        self._lock = asyncio.Lock()

    def add_api_key(self, api_key: str):
        self._add_cli_api_key(api_key)
    
    async def check_api_key(self):
        if not self._api_keys:
            self.print_error("Missing, disabling module")
            self._enabled = False
            return
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        while self._activate_next_api_key():
            headers = {"accept": "application/json", "x-apikey": self._api_key}
            retry = self._retry
            while retry > 0:
                try:
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get('https://www.virustotal.com/api/v3/domains/example.com', headers=headers) as response:
                            if response.status == 200:
                                self.print_ok("Present")
                                self._enabled = True
                                return

                            break
                except TimeoutError:
                    await asyncio.sleep(2)
                    retry -= 1
        self.print_error("Invalid, disabling module")
        self._enabled = False

    async def __get_resolutions(self, domain: str):
        headers = {"accept": "application/json", "x-apikey": self._api_key}
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        datasource_objects = []
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=40"
        async with aiohttp.ClientSession(timeout=timeout) as session:
            while url is not None:
                async with session.get(url, headers=headers) as response:
                    if response.status != 200:
                        if response.status == 429:
                            if not self._activate_next_api_key():
                                raise IndexError
                            headers = {"accept": "application/json", "x-apikey": self._api_key}
                            continue
                        async with self._lock:
                            if self._enabled:
                                self._enabled = False
                                self.print_error(
                            (await response.json()).get('error', {}).get('message', "Unspecified error."))
                        return datasource_objects
                    data = await response.json()
                    try:
                        domain_data = data.get('data', [])
                        dns_data = []
                        for record in domain_data:
                            ip = record.get('attributes', {}).get('ip_address', '')
                            dns_data.append(DNSRecordGenerator(source=__class__.__name__, 
                                record_last_seen=date_from_utc(record.get('attributes',{}).get('date',None)),
                                type='A', value=ip, ttl=None, verified=False
                                ))
                        datasource_object = DatasourceObject(
                            domain=domain,
                            DNSData=dns_data)
                        datasource_objects.append(datasource_object)
                        url = data.get('links',{}).get('next', None)
                    except Exception as e:
                        self.print_error(f"Unspecified error: {e}")
                        url = None
        return datasource_objects

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
                                    if not self._activate_next_api_key():
                                        raise IndexError
                                    headers = {"accept": "application/json", "x-apikey": self._api_key}
                                    continue
                                return domain_list
                            data = await response.json()
                            try:
                                domain_data = data.get('data', [])
                                for record in domain_data:
                                    subdomain = record.get('id', '')
                                    self.print_ok(f"Found subdomain {subdomain}", clear_to_eol=True, end='\r')
                                    datasource_object = DatasourceObject(domain=subdomain, DNSData=[DNSRecordGenerator(**x,source=__class__.__name__, record_last_seen=date_from_utc(record.get('attributes',{}).get('last_dns_records_date',None))) for x in record.get('attributes',{}).get('last_dns_records',[])])
                                    domain_list.append(subdomain)
                                    datasource_objects.append(datasource_object)
                                    resolutions = await self.__get_resolutions(subdomain)
                                    datasource_objects.extend(resolutions)
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
            except IndexError:
                self.print_error(f"No more API keys available.")
                return datasource_objects
        self.print_error(f"Max timeout reached for {domain}. SKIPPING.")
        return []

    async def reverse_search(self, IP: str):
        if not self._enabled:
            return []
        datasource_objects = []
        if self._barier:
            self.print_info(f"Started search for IP {self.scandidate}")
            self._barier = False
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
                                if response.status == 429:
                                    if not self._activate_next_api_key():
                                        raise IndexError
                                    headers = {"accept": "application/json", "x-apikey": self._api_key}
                                    continue
                                async with self._lock:
                                    if self._enabled:
                                        self._enabled = False
                                        self.print_error(
                                    (await response.json()).get('error', {}).get('message', "Unspecified error."))
                                return domain_list
                            data = await response.json()
                            try:
                                domain_data = data.get('data', [])
                                for record in domain_data:
                                    subdomain = record.get('attributes', {}).get('host_name', '')
                                    datasource_object = DatasourceObject(domain=subdomain, DNSData=[DNSRecordGenerator(type="A",source=__class__.__name__,ttl=None,value=IP, record_last_seen=date_from_utc(record.get('attributes',{}).get('date',None)))])
                                    domain_list.append(subdomain)
                                    datasource_objects.append(datasource_object)
                                next_url = data.get('links',{}).get('next', None)
                            except Exception as e:
                                self.print_error(f"Unspecified error: {e}")
                                next_url = None
                #return list(set(domain_list))
                if self._end_barier:
                    self.print_info(f"Finished search for IP {self.scandidate}")
                    self._end_barier = False
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"{self.scandidate} lookup canceled.")
                return datasource_objects
            except StopIteration:
                self.print_error(f"Could not get more records from VirusTotal API.")
                return datasource_objects
            except TimeoutError:
                self.print_warning(f"Timed out when fetching data for IP {self.scandidate}. Trying again. ({i + 1}/{self.retry})")
                await asyncio.sleep(2)
            except IndexError:
                async with self._lock:
                    if self._enabled:
                        self.print_error(f"No more API keys available.")
                    self._enabled = False
                return datasource_objects
        self.print_error(f"Max timeout reached for IP {self.scandidate}. SKIPPING.")
        return []
