import argparse
import asyncio
import aiofiles
import re
import os
import punycode

from ptodnes.DNS.dnsinfo import DNSInfo
from ptodnes.DNS.record import DNSRecord
import ptodnes.datasources
import ptodnes.dataexporter
from ptodnes.DNS.odnesdns import OdnesDNS
from ptodnes.DNS.dns_record_dict import DNSRecordDict
from ptlibs.ptprinthelper import out_if, ptprint
from ptodnes.factchecker.factchecker import VhostFactChecker


def domain_parser(arg_value):
    if arg_value.endswith('.'):
        arg_value = arg_value[:-1]
    try:
        arg_value = punycode.convert(arg_value, True)
    except:
        pass
    rgx = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$')
    if not rgx.match(arg_value):
        raise argparse.ArgumentTypeError("Invalid domain name")
    return arg_value

def ipv4(arg_value):

    ip6 = re.compile(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
    if ip6.match(arg_value):
        raise argparse.ArgumentTypeError("IPv6 not supported yet")
    pattern = re.compile(r"^(((?!25?[6-9])[12]\d|[1-9])?\d\.?\b){4}(\/(\d{1,2}))?$")
    if not pattern.match(arg_value):
       raise argparse.ArgumentTypeError("Invalid IPv4 address or CIDR block")
    return arg_value

async def process(loop: asyncio.AbstractEventLoop,
                  /,
                  *,
                  api:list=None,
                  domain:list=None,
                  datasource:list=None,
                  wordlist:list=None,
                  config:str=None,
                  type:list=None,
                  ip_address:list=None,
                  web_apps:bool=False,
                  output:str=None,
                  nonxdomain:bool=False,
                  verbose:int=3,
                  very_verbose:bool=False,
                  retry:int=5,
                  timeout:int=5,
                  query:bool=False,
                  exclude_unverified:bool=False,
                  format:str=None,
                  file_domains:str=None,
                  file_ip:str=None,
                  **kwargs,) -> DNSRecordDict | None:

    """
    :param loop: asyncio event loop
    :param domains: list of domains to search
    :param selected_datasources: list of datasources to search
    :param types: list of types to search
    :param nonxdomain: whether to include nonxdomain records
    :param query: whether to query records against DNS server
    :param exclude: whether to exclude records not present on DNS server
    :param output_format: output format, valid inputs are 'json, csv or yaml'
    :param silent: if False, ptlibs output will be printed
    :param verbosity: set verbosity level for ptlibs
    :param timeout: timeout for each datasource in seconds
    :param retry: retry rate for each datasource
    :return: `DNSRecordDict` with all found data or `None`
    """
    silent = True
    if format: silent = False

    odnesdns = OdnesDNS()
    odnesdns.set_loop(loop)

    if (domain or file_domains) and (ip_address or file_ip):
        if file_domains:
            if not domain:
                domain = []
            try:
                async with aiofiles.open(file_domains) as fd:
                    async for line in fd:
                        if domain_parser(line) not in domain:
                            try:
                                domain.append(domain_parser(line))
                            except argparse.ArgumentTypeError:
                                continue
            except PermissionError:
                ptprint(out_if(f"Permissions denied for {file_domains}", "ERROR", silent, colortext=True))
                return DNSRecordDict()
            except FileNotFoundError:
                ptprint(out_if(f"Domains file {file_domains} not found", "ERROR", silent, colortext=True))
            except IsADirectoryError:
                ptprint(out_if(f"Domains file {file_domains} is not a file", "ERROR", silent, colortext=True))
                return DNSRecordDict()
            except Exception as e:
                ptprint(out_if(e, "ERROR", silent, colortext=True))
                return DNSRecordDict()
        if file_ip:
            if not ip_address:
                ip_address = []
            try:
                async with aiofiles.open(file_ip) as fi:
                    async for line in fi:
                        if ipv4(line) not in ip_address:
                            try:
                                ip_address.append(domain_parser(ipv4(line)))
                                print(ip_address)
                            except argparse.ArgumentTypeError:
                                continue
            except PermissionError:
                ptprint(out_if(f"Permissions denied for {file_domains}", "ERROR", silent, colortext=True))
                return DNSRecordDict()
            except FileNotFoundError:
                ptprint(out_if(f"Domains file {file_domains} not found", "ERROR", silent, colortext=True))
            except IsADirectoryError:
                ptprint(out_if(f"Domains file {file_domains} is not a file", "ERROR", silent, colortext=True))
                return DNSRecordDict()
            except Exception as e:
                raise e
                ptprint(out_if(e, "ERROR", silent, colortext=True))
                return DNSRecordDict()
        
        res = DNSRecordDict()
        for dom in domain:
            res[dom] = DNSInfo(domain=dom, records=[])
        await odnesdns.query(res, qtype='A')
        res.filterNX()
        res.filter_untrusted()
        for ip in ip_address:
            baseline = DNSRecord(type='A', value=ip, source={'Baseline'}, verified=True, record_last_seen=None, ttl=None)
            for domain, info in res.items():
                if baseline in info.records:
                    res[domain].matches = True
        if web_apps:
            for ip in ip_address:
                checker = await VhostFactChecker.create(ip, timeout=timeout)
                for domain, info in res.items():
                    await checker.find_vhosts(info)
        return res




    ptprint(out_if(f"Load datasource modules", "INFO", silent, colortext=True))
    if '_' in datasource:
        ptodnes.datasources.load_datasource(None, silent)
    else:
        for selected_datasource in datasource:
            ptodnes.datasources.load_datasource(selected_datasource, silent)
    for datasource_instance in ptodnes.datasources.datasources.values():
        datasource_instance.on_load()
    print()

    if api:
        for ds, api_key in api:
            if ds.lower() in ptodnes.datasources.list_datasources():
                ptodnes.datasources.datasources[ds.lower()].add_api_key(api_key)

    ptprint(out_if(f"Check API keys", "INFO", silent, colortext=True))
    for datasource_instance in ptodnes.datasources.datasources.values():
        await datasource_instance.check_api_key()
    print()


    try:
        ds_tasks = []
        domains = list(set(domain if domain else []))
        if '_' in datasource:
            for datasource in ptodnes.datasources.datasources.values():
                datasource.timeout = timeout
                datasource.retry = retry
                datasource.wordlists = wordlist
                datasource.set_verbose(silent)
                datasource.set_verbose_level(verbose)
                for domain in domains if domains else []:
                    task = loop.create_task(datasource.search(domain))
                    ds_tasks.append(task)
                for ip in ip_address if ip_address else []:
                    task = loop.create_task(datasource.reverse_search(ip))
                    ds_tasks.append(task)
        else:
            for selected_datasource in datasource:
                datasource = ptodnes.datasources.datasources.get(selected_datasource, None)
                if not datasource:
                    continue
                datasource.timeout = timeout
                datasource.retry = retry
                datasource.wordlists = wordlist
                datasource.set_verbose(silent)
                datasource.set_verbose_level(verbose)
                for domain in domains if domains else []:
                    task = loop.create_task(datasource.search(domain))
                    ds_tasks.append(task)
                for ip in ip_address if ip_address else []:
                    task = loop.create_task(datasource.reverse_search(ip))
                    ds_tasks.append(task)

        data = await asyncio.gather(*ds_tasks)
        merged = [j for i in data for j in i]

        res = DNSRecordDict()

        res.extend(merged)

        # If requested, detect web applications (vhosts) on provided IPs.
        # This is currently implemented only for combination with -ip.
        if web_apps and ip_address:
            # domains to test are all domains we discovered
            qtypes = ["A"]
            qtasks = []
            for qtype in qtypes:
                task = loop.create_task(odnesdns.query(res, qtype=qtype))
                qtasks.append(task)
            await asyncio.gather(*qtasks)
            for ip in ip_address:
                checker = await VhostFactChecker.create(ip, timeout=timeout)
                for domain, info in res.items():
                    await checker.find_vhosts(info)
            return res

        if query:
            qtypes = type.copy()
            if "ANY" in type:
                qtypes = ['A', 'AAAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SRV', 'TXT',]

            qtasks = []
            for qtype in qtypes:
                task = loop.create_task(odnesdns.query(res, qtype=qtype))
                qtasks.append(task)
            await asyncio.gather(*qtasks)

        res.filter(type)

        if exclude_unverified:
            res.filter_untrusted()

        if nonxdomain:
            res.filterNX()

        return res
    except asyncio.CancelledError:
        pass