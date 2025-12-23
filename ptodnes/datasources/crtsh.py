import asyncio
import re
from sqlite3 import OperationalError

from ptodnes.datasources.datasource import Datasource, DatasourceObject, DNSRecordGenerator
import aiopg

class CRTsh(Datasource):
    _pg_url: str = "dbname=certwatch user=guest host=91.199.212.73"
    def __init__(self):
        super().__init__()

    def add_api_key(self, api_key: str = None):
        pass

    async def check_api_key(self):
        self.print_warning("API key not required")

    async def search(self, domain: str):
        try:
            self.print_info(f"Started search for domain {domain}")
            for i in range(self.retry):
                try:
                    datasource_objects = []
                    async with aiopg.create_pool(self._pg_url, timeout=self.timeout) as pool:
                        async with pool.acquire() as conn:
                            async with conn.cursor() as cur:
                                query = """
                                SELECT DISTINCT sub.NAME_VALUE 
                                FROM (
                                    SELECT cai.* 
                                    FROM certificate_and_identities cai 
                                    WHERE plainto_tsquery('certwatch', %s) 
                                    @@ identities(cai.CERTIFICATE) 
                                    AND cai.NAME_VALUE ILIKE %s 
                                    LIMIT 10000
                                ) sub;
                                """
                                param_domain = f"%{domain}%"
                                await cur.execute(query, (domain, param_domain))

                                ret = []
                                rgx = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$')
                                async for row in cur:
                                    if '@' in row[0]:
                                        continue
                                    if row[0].startswith('*'):
                                        if row[0][2:] not in ret:
                                            subdomain = row[0][2:]
                                            if not rgx.match(subdomain):
                                                continue
                                            self.print_ok(f"Found subdomain: {subdomain}")
                                            datasource_object = DatasourceObject(domain=subdomain, DNSData=[DNSRecordGenerator(source=self.__class__.__name__, type=None, verified=False, value=None, ttl=None, record_last_seen=None)])
                                            datasource_objects.append(datasource_object)
                                            ret.append(subdomain)
                                    else:
                                        if row[0] not in ret:
                                            subdomain = row[0]
                                            if not rgx.match(subdomain):
                                                continue
                                            self.print_ok(f"Found subdomain: {subdomain}")
                                            datasource_object = DatasourceObject(domain=subdomain, DNSData=[DNSRecordGenerator(source=self.__class__.__name__, type=None, verified=False, value=None, ttl=None, record_last_seen=None)])
                                            datasource_objects.append(datasource_object)
                                            ret.append(subdomain)
                                if domain not in ret:
                                    ret.append(domain)
                                    datasource_objects.append(DatasourceObject(domain=domain, DNSData=[DNSRecordGenerator(source=self.__class__.__name__, type=None, verified=False, value=None, ttl=None, record_last_seen=None)]))
                        self.print_info(f"Finished search for domain {domain}")
                        pool.close()
                        await pool.wait_closed()
                        return datasource_objects
                except TimeoutError:
                    self.print_warning(f"Timed out when fetching data for {domain}. Trying again. ({i+1}/{self.retry})")
                    await asyncio.sleep(2)
                except OperationalError:
                    self.print_error(f"Error when fetching data for {domain}. CRTsh is not accepting connections.")
                    return []
        except asyncio.exceptions.CancelledError:
            self.print_warning(f"{domain} lookup canceled.")
            return []
        self.print_error(f"Max timeout reached for {domain}. SKIPPING.")
        return []

    async def reverse_search(self, domain: str):
        self.print_warning("IP address lookup is not supported.")
        return []
