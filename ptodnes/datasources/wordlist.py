import asyncio
import sys
import aiofiles
import re

from ptodnes.datasources.datasource import Datasource, DatasourceObject, DNSRecordGenerator
from ptodnes.DNS.odnesdns import OdnesDNS

from ptodnes.DNS.dns_record_dict import DNSRecordDict

import punycode
import os

from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeRemainingColumn,
)

class Wordlist(Datasource):

    def __init__(self, api_key: str = ''):
        super().__init__()
        wordlists_cfg = self.config.get("wordlists", [])
        self._enabled = self.config.get('enabled', True)
        if type(wordlists_cfg) is type(''):
            self.__wordlists = [wordlists_cfg]
        else:
            self.__wordlists = wordlists_cfg

    async def check_api_key(self):
        pass

    def add_api_key(self, api_key: str = None):
        pass

    async def search(self, domain: str):
        if not self._enabled:
            return []
        if self._wordlists:
            self.__wordlists = self._wordlists
        self.print_info("Started wordlist search")
        dns = OdnesDNS()
        datasource_objects = []
        rgx = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$')
        async for sub in self.read_wordlist():
            subdomain = sub + '.' + domain if sub else domain
            d = ''
            try:
                d = subdomain
                subdomain = punycode.convert(subdomain, True)
            except:
                continue
            if rgx.match(subdomain):
                datasource_object = DatasourceObject(domain=subdomain, DNSData=[
                    DNSRecordGenerator(source=self.__class__.__name__, type='<NONE>', verified=False, value="<EMPTY>",
                                       ttl=None,
                                       record_last_seen=None)])
                datasource_objects.append(datasource_object)
        res = DNSRecordDict()
        res.extend(datasource_objects)

        qtypes: list
        if self._qtype:
            qtypes = self._qtype
        else:
            qtypes = ['A', 'AAAA', 'CNAME']

        qtasks = []
        total_domains = len(res)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            transient=True,
            redirect_stdout=True,
        ) as progress:
            task_map: dict[str, int] = {}
            for qtype in qtypes:
                task_map[qtype] = progress.add_task(f"Querying {qtype}", total=total_domains)

            for qtype in qtypes:
                # bind qtype into lambda default to avoid late binding
                def make_progress_func(tid):
                    return lambda max, cur, label: progress.update(tid, total=max, completed=cur)

                task = dns.get_loop().create_task(
                    dns.query(res, qtype=qtype, print_func=self.print_info, progress_func=make_progress_func(task_map[qtype]))
                )
                qtasks.append(task)

            await asyncio.gather(*qtasks)
        if self._verbose:
            print()
        res.filter_untrusted()

        return res.as_list()

    async def reverse_search(self, IP: str):
        if not self._enabled:
            return []
        if self._barier:
            self.print_warning("IP address lookup is not supported.")
            self._barier = False
        return []

    async def read_wordlist(self):
        for wordlist in self.__wordlists:
            try:
                self.print_info(f"Reading wordlist {wordlist}")
                file_size = os.path.getsize(wordlist)
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    transient=True,
                    redirect_stdout=True,
                ) as progress:
                    task_id = progress.add_task("Reading wordlist", total=file_size)
                    async with aiofiles.open(wordlist, 'r') as wordlist_file:
                        async for line in wordlist_file:
                            # advance by byte length of the line to reflect file progress
                            try:
                                advance_bytes = len(line.encode('utf-8'))
                            except Exception:
                                advance_bytes = len(line)
                            progress.update(task_id, advance=advance_bytes)
                            if line.endswith('\n'):
                                line = line[:-1]
                            yield line
                self.print_info("Reading done")
            except PermissionError:
                self.print_error(f"Permissions denied for '{wordlist}'")
                continue
            except FileNotFoundError:
                self.print_error(f"Domains file '{wordlist}' not found")
                continue
            except IsADirectoryError:
                self.print_error(f"Domains file '{wordlist}' is not a file")
                continue
            except Exception as e:
                self.print_error(str(e))
                continue