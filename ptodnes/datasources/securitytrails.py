import aiohttp
import asyncio
from ptodnes.datasources.datasource import Datasource, DatasourceObject, DNSRecordGenerator


class SecurityTrails(Datasource):
    _api_key: str = ""
    _api_url: str = "https://api.securitytrails.com/v1/domains/list?include_ips=true&page={page}"
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
            async with self._lock:
                self._enabled = False
            return
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        while self._activate_next_api_key():
            headers = {"accept": "application/json", "APIKEY": self._api_key}
            retry = self._retry
            while retry > 0:
                try:
                    async with aiohttp.ClientSession(timeout=timeout) as session:
                        async with session.get('https://api.securitytrails.com/v1/ping', headers=headers) as response:
                            if response.status == 200:
                                self.print_ok("Present")
                                async with self._lock:
                                    self._enabled = True
                                return

                            break
                except TimeoutError:
                    await asyncio.sleep(2)
                    retry -= 1
        self.print_error("Invalid, disabling module")
        async with self._lock:
            self._enabled = False

    
    
    async def search(self, domain: str):
        """
        Search for `resource` information for `domain` in SecurityTrails.

        :param domain: The domain to search for.
        :return: `DatasourceObject` object if domain is found, None otherwise
        """
        if not self._enabled:
            return []
        datasource_objects = []
        self.print_info(f"Started search for domain {domain}")
        for i in range(self.retry):
            try:
                domain_list = []
                next_url = self._api_url.format(page=1)
                body = {'filter':{'apex_domain': domain}}
                headers = {"accept": "application/json", "APIKEY": self._api_key}
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    while next_url is not None:
                        async with session.post(next_url, headers=headers, json=body) as response:
                            if response.status != 200:
                                if response.status == 429:
                                    async with self._lock:
                                        if not self._activate_next_api_key():
                                            raise IndexError
                                        headers = {"accept": "application/json", "APIKEY": self._api_key}
                                    continue
                                self.print_error(f' API returned {response.status}:{await response.text()}')
                                return datasource_objects
                            data = await response.json()
                            domain_meta = data.get('meta', {})
                            domain_data = data.get('records', [])
                            page = domain_meta.get('page')
                            max_page = domain_meta.get('max_page')
                            total_pages = domain_meta.get('total_pages')
                            if page < max_page:
                                next_url = self._api_url.format(page=page+1)
                            else:
                                next_url = None
                                if max_page < total_pages:
                                    self.print_warning(f"Max pages reached {page}/{total_pages}, stopping. Consider API upgrade.")
                            for record in domain_data:
                                subdomain = record.get('hostname', '')
                                self.print_ok(f"Found subdomain {subdomain}", clear_to_eol=True, end='\r')
                                datasource_object = DatasourceObject(domain=subdomain, DNSData=[DNSRecordGenerator(type='A', value=x, ttl=-1, source=__class__.__name__, record_last_seen=None) for x in record.get('ips',[])])
                                domain_list.append(subdomain)
                                datasource_objects.append(datasource_object)
                if domain not in domain_list:
                    domain_list.append(domain)
                #return list(set(domain_list))
                self.print_info(f"Finished search for domain {domain}")
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"{domain} lookup canceled.")
                return datasource_objects
            except StopIteration:
                self.print_error(f"Could not get more records from SecurityTrails API.")
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
                next_url = self._api_url.format(page=1)
                body = {'filter': {'ipv4': IP}}
                headers = {"accept": "application/json", "APIKEY": self._api_key}
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    while next_url is not None:
                        async with session.post(next_url, headers=headers, json=body) as response:
                            if response.status != 200:
                                if response.status == 429:
                                    async with self._lock:
                                        if not self._activate_next_api_key():
                                            raise IndexError
                                        headers = {"accept": "application/json", "APIKEY": self._api_key}
                                    continue
                                self.print_error(f' API returned {response.status}:{await response.text()}')
                                return datasource_objects
                            data = await response.json()
                            domain_meta = data.get('meta', {})
                            domain_data = data.get('records', [])
                            page = domain_meta.get('page')
                            max_page = domain_meta.get('max_page')
                            total_pages = domain_meta.get('total_pages')
                            if page < max_page:
                                next_url = self._api_url.format(page=page + 1)
                            else:
                                next_url = None
                                if max_page < total_pages:
                                    self.print_warning(
                                        f"Max pages reached {page}/{total_pages}, stopping. Consider API upgrade.")
                            for record in domain_data:
                                subdomain = record.get('hostname', '')
                                datasource_object = DatasourceObject(domain=subdomain, DNSData=[
                                    DNSRecordGenerator(type='A', value=x, ttl=-1, source=__class__.__name__,
                                                       record_last_seen=None) for x in record.get('ips', [])])
                                domain_list.append(subdomain)
                                datasource_objects.append(datasource_object)
                # return list(set(domain_list))
                if self._end_barier:
                    self.print_info(f"Finished search for IP {self.scandidate}")
                    self._end_barier = False
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"IP {self.scandidate} lookup canceled.")
                return datasource_objects
            except StopIteration:
                self.print_error(f"Could not get more records from SecurityTrails API.")
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
        self.print_error(f"Max timeout reached for {self.scandidate}. SKIPPING.")
        return []
