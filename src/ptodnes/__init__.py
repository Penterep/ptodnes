import asyncio
import signal

import ptodnes.datasources
import ptodnes.dataexporter
from ptodnes.DNS.odnesdns import OdnesDNS
from ptodnes.DNS.dns_record_dict import DNSRecordDict
import re
from ptlibs.ptprinthelper import out_if, ptprint
import punycode

def add_signal_handlers():
    """
    Properly handles SIGINT and SIGTERM signals. Ensures correct end of all coroutines.
    :return:
    """
    loop = asyncio.get_event_loop()

    async def shutdown(_: signal.Signals) -> None:
        """
        Cancel all running async tasks (other than this one) when called.
        By catching asyncio.CancelledError, any running task can perform
        any necessary cleanup when it's cancelled.
        """
        for task in asyncio.all_tasks(loop):
            if task is not asyncio.current_task(loop):
                task.cancel()

    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(sig)))


async def process(loop: asyncio.AbstractEventLoop,
                  domains: list,
                  selected_datasources: list,
                  types: list,
                  nonxdomain: bool,
                  query: bool,
                  exclude: bool,
                  output_format: str,
                  silent: bool,
                  verbosity: int,
                  timeout: int,
                  retry: int,
                  wordlists: list) -> DNSRecordDict | None:
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
    if output_format: silent = False
    try:
        ds_tasks = []
        domains = list(set(domains))
        for domain in domains:
            if domain.endswith('.'):
                domain = domain[:-1]
            domain = punycode.convert(domain, True)
            rgx = re.compile(r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$')
            if not rgx.match(domain):
                ptprint(out_if(f"{domain} is not a valid domain name, SKIPPING", "WARNING", silent, colortext=True))
                continue
            if 'ANY' in selected_datasources:
                for datasource in ptodnes.datasources.datasources.values():
                    datasource.timeout = timeout
                    datasource.retry = retry
                    datasource.wordlists = wordlists
                    datasource.set_verbose(silent)
                    datasource.set_verbose_level(verbosity)
                    task = loop.create_task(datasource.search(domain))
                    ds_tasks.append(task)
            else:
                for selected_datasource in selected_datasources:
                    datasource = ptodnes.datasources.datasources[selected_datasource]
                    datasource.timeout = timeout
                    datasource.retry = retry
                    datasource.wordlists = wordlists
                    datasource.set_verbose(silent)
                    datasource.set_verbose_level(verbosity)
                    task = loop.create_task(datasource.search(domain))
                    ds_tasks.append(task)
        data = await asyncio.gather(*ds_tasks)
        merged = [j for i in data for j in i]

        res = DNSRecordDict()

        res.extend(merged)

        if query:
            odnesdns = OdnesDNS(loop)
            qtypes = types.copy()
            if "ANY" in types:
                qtypes = ['A', 'AAAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SRV', 'TXT',]

            qtasks = []
            for qtype in qtypes:
                task = loop.create_task(odnesdns.query(res, qtype=qtype))
                qtasks.append(task)
            await asyncio.gather(*qtasks)

        res.filter(types)

        if exclude:
            res.filter_untrusted()

        if nonxdomain:
            res.filterNX()

        return res
    except asyncio.CancelledError:
        pass