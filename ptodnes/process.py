import asyncio

import ptodnes.datasources
import ptodnes.dataexporter
from ptodnes.DNS.odnesdns import OdnesDNS
from ptodnes.DNS.dns_record_dict import DNSRecordDict
import re
from ptlibs.ptprinthelper import out_if, ptprint
import punycode


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
                  output:str=None,
                  nonxdomain:bool=False,
                  verbose:int=3,
                  very_verbose:bool=False,
                  retry:int=5,
                  timeout:int=5,
                  query:bool=False,
                  exclude_unverified:bool=False,
                  format:str=None,
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

        if query:
            odnesdns = OdnesDNS(loop)
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