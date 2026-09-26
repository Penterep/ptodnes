import aiohttp
import asyncio
from ptodnes.datasources.datasource import Datasource, DatasourceObject, date_from_iso, DNSRecordGenerator

class HackerTarget(Datasource):
    _api_url: str = "https://api.hackertarget.com/{tool}/?q={target}"

    def __init__(self, api_key: str = ''):
        super().__init__()
        self._enabled = self.config.get('enabled', True)
        self._load_api_keys(api_key)

    def add_api_key(self, api_key: str):
        # HackerTarget doesn't require API keys for public endpoints, but keep interface
        self._add_cli_api_key(api_key)

    async def check_api_key(self):
        # Public API; just report presence
        self.print_ok("API key not required")

    async def search(self, domain: str):
        """
        Search for subdomains for `domain` using HackerTarget `hostsearch`.

        Returns list of `DatasourceObject` with `DNSRecordGenerator(type='A', ...)` entries,
        matching the output format used by `securitytrails.py`.
        """
        if not self._enabled:
            return []
        datasource_objects = []
        self.print_info(f"Started search for domain {domain}")
        for i in range(self.retry):
            try:
                domain_list = []
                url = self._api_url.format(tool="hostsearch", target=domain)
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as response:
                        if response.status != 200:
                            text = await response.text()
                            self.print_error(f"Failed to retrieve data from HackerTarget. Status: {response.status} - {text}")
                            return []
                        data = await response.text()
                        lines = data.splitlines()
                        for line in lines:
                            if ',' in line:
                                subdomain, ip_address = line.split(',', 1)
                                subdomain = subdomain.strip()
                                ip_address = ip_address.strip()
                                if subdomain not in domain_list:
                                    self.print_ok(f"Found subdomain {subdomain}", clear_to_eol=True, end='\r')
                                    dnslist = [DNSRecordGenerator(type='A', value=ip_address, ttl=-1, source=__class__.__name__, record_last_seen=None)]
                                    datasource_object = DatasourceObject(domain=subdomain, DNSData=dnslist)
                                    domain_list.append(subdomain)
                                    datasource_objects.append(datasource_object)
                if domain not in domain_list:
                    domain_list.append(domain)
                self.print_info(f"Finished search for domain {domain}")
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"{domain} lookup canceled.")
                return datasource_objects
            except TimeoutError:
                self.print_warning(f"Timed out when fetching data for {domain}. Trying again. ({i + 1}/{self.retry})")
                await asyncio.sleep(2)
            except Exception as e:
                self.print_error(f"Error during search: {e}")
                await asyncio.sleep(2)
        self.print_error(f"Max timeout reached for {domain}. SKIPPING.")
        return []

    async def reverse_search(self, IP: str):
        """
        Reverse IP lookup using HackerTarget `reverseiplookup` endpoint.
        """
        if not self._enabled:
            return []
        datasource_objects = []
        if self._barier:
            self.print_info(f"Started search for IP {self.scandidate}")
            self._barier = False
        for i in range(self.retry):
            try:
                url = self._api_url.format(tool="reverseiplookup", target=IP)
                timeout = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(url) as response:
                        if response.status != 200:
                            text = await response.text()
                            self.print_error(f"Failed to retrieve data from HackerTarget. Status: {response.status} - {text}")
                            return []
                        data = await response.text()
                        lines = data.splitlines()
                        for line in lines:
                            domain = line.strip()
                            if domain:
                                self.print_ok(f"Found domain {domain}", clear_to_eol=True, end='\r')
                                dnsrec = DNSRecordGenerator(type='A', value=IP, ttl=-1, source=__class__.__name__, record_last_seen=None)
                                datasource_objects.append(DatasourceObject(domain=domain, DNSData=[dnsrec]))
                if self._end_barier:
                    self.print_info(f"Finished search for IP {self.scandidate}")
                    self._end_barier = False
                return datasource_objects
            except asyncio.exceptions.CancelledError:
                self.print_warning(f"{self.scandidate} lookup canceled.")
                return datasource_objects
            except TimeoutError:
                self.print_warning(f"Timed out when fetching data for IP {self.scandidate}. Trying again. ({i + 1}/{self.retry})")
                await asyncio.sleep(2)
            except Exception as e:
                self.print_error(f"Error during reverse search: {e}")
                await asyncio.sleep(2)
        self.print_error(f"Max timeout reached for IP {IP}. SKIPPING.")
        return []