import argparse
import asyncio
import pathlib
import re
from argparse import ArgumentParser
import sys
import os
import punycode

import ptodnes.process
import ptodnes.datasources
import ptodnes.dataexporter
from ptodnes import dataexporter
from ptodnes.DNS.odnesdns import OdnesDNS
from ptodnes.configprovider.configprovider import ConfigProvider
from ptlibs.ptprinthelper import help_print, print_banner, ptprint
import importlib.metadata



__version__ = importlib.metadata.version(__package__)
__scriptname__ = os.path.basename(sys.argv[0])

def domain(arg_value):
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
    pattern = re.compile(r"^(((?!25?[6-9])[12]\d|[1-9])?\d\.?\b){4}$")
    if not pattern.match(arg_value):
        raise argparse.ArgumentTypeError("Invalid IPv4 address")
    return arg_value


def get_help():
    return [
        {"description": ["DNS Enumeration Tool"]},
        {"usage": [f"{__scriptname__} <options>"]},
        {"usage_example": [
            f"{__scriptname__} -l",
            f"{__scriptname__} -d example.com",
            f"{__scriptname__} -d example.com example.net",
            f"{__scriptname__} -d example.com -D VirusTotal CRTsh",
            f"{__scriptname__} -d example.com -j -o example -t A AAAA",
        ]},
        {"Info": [
            "If no datasource set, all available will be used",
            "Only one of -j -y or -c may be used",
        ]},
        {"options": [
            ["-api", "--api", "<module> <api_key>", "Set API key for module"],
            ["-c", "--csv", "", "Output in CSV format"],
            ["-C", "--config", "<config>", "Path to config file (default ~/ptodnes.toml)"],
            ["-d", "--domain", "<domain ...>", "Domains to search for"],
            ["-D", "--datasource", "<datasource ...>", "Datasources to browse"],
            ["-e", "--exclude-unverified", "", "Exclude unverified records"],
            ["-ip", "--ip-address", "<ip address ...>", "IP to search for"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-l", "--list", "", "List available datasources"],
            ["-n", "--nonxdomain", "", "Filter results with no DNS data"],
            ["-o", "--output", "<file_prefix>", "Save results to files (format specification required)"],
            ["-q", "--query", "", "Query domains against DNS servers"],
            ["-r", "--retry", "<count>", "Number of attempts (default:5)"],
            ["-t", "--type", "<type ...>", "Types of DNS records to search for"],
            ["-T", "--timeout", "<timeout>", "Datasource connection timeout (in seconds, default:5)"],
            ["-v", "--version", "", "Print version and exit"],
            ["-V", "--verbose", "<1|2|3|4>", "Set verbosity level (1=ERROR, 2=WARNING, 3=INFO, 4=DEBUG)"],
            ["-vv", "--very-verbose", "", "Output more information"],
            ["-w", "--wordlist", "<wordlist ...>", "Path to wordlist(s) for wordlist search"],
            ["-y", "--yaml", "", "Output in YAML format"],
        ]
        }]

async def main(loop):
    if sys.platform != 'win32':
        ptodnes.add_signal_handlers()
    parser = ArgumentParser(add_help=False)
    parser.add_argument('-api', '--api', help="Set API key for module", action='append', nargs=2, metavar=('Module', 'API_KEY'))
    parser.add_argument("-l", "--list", help="list available datasources", action="store_true", default=False)
    parser.add_argument("-d",
                        "--domain",
                        help="domain to search for",
                        nargs='+',
                        required=(('-l' not in sys.argv and '--list' not in sys.argv) and ('-ip' not in sys.argv and '--ip-address' not in sys.argv)),
                        type=domain)
    parser.add_argument("-D",
                        "--datasource",
                        nargs='+',
                        help="Datasource to search",
                        metavar="DATASOURCE",
                        choices=ptodnes.datasources.list_datasources(),
                        default="_",
                        type=str.lower)
    parser.add_argument("-w", "--wordlist", help="path to wordlist for searching", nargs='+', metavar="WORDLIST", type=str)
    parser.add_argument("-C", "--config", help="config file to use", type=str)
    parser.add_argument("-s", "--silent", help="disable verbose output", action="store_false", default=True)
    parser.add_argument("-t",
                        "--type",
                        nargs='+',
                        help="types of DNS records to search for",
                        metavar="TYPE",
                        choices=['ANY', 'A', 'AAAA', 'CNAME', 'MX', 'NAPTR', 'NS', 'PTR', 'SOA', 'SRV', 'TXT',],
                        default=["ANY"],
                        type=str)
    parser.add_argument("-ip", "--ip-address", help="ip for reverse lookup", type=ipv4, nargs='+', metavar="IP")
    parser.add_argument("-n", "--nonxdomain", help="disable output of NXDOMAIN", action="store_true", default=False)
    parser.add_argument("-V", "--verbose", help="verbosity level (1=ERROR, 2=WARNING, 3=INFO, 4=DEBUG)", type=int, default=3)
    parser.add_argument("-v", "--version", help="print version and exit", action="store_true", default=False)
    parser.add_argument("-r", "--retry", help="number of attempts", default=5, type=int)
    parser.add_argument("-T", "--timeout", help="timeout (in seconds)", default=5, type=int)
    parser.add_argument("-q", "--query", help="query domains against DNS servers", action="store_true", default=False, required=('-e' in sys.argv or '--exclude-unverified' in sys.argv))
    parser.add_argument("-e", "--exclude-unverified", help="exclude unverified records", action="store_true", default=False)

    format_parser = parser.add_mutually_exclusive_group(required=('-o' in sys.argv or '--output' in sys.argv))
    format_parser.add_argument("-y", "--yaml", help="output in YAML format", action="store_const", const="yaml", dest="format")
    format_parser.add_argument("-c", "--csv", help="output in CSV format", action="store_const", const="csv", dest="format")
    format_parser.add_argument("-j", "--json", help="output in ptJSONlib format", action="store_const", const="ptjson",
                               dest="format")

    output = parser.add_mutually_exclusive_group()
    output.add_argument("-o", "--output", help="save results to files", type=str)
    output.add_argument("-vv", "--very-verbose", help="set very verbose mode", action="store_true", default=False)

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        help_print(get_help(), __scriptname__, __version__)
        exit(1)
    if "-v" in sys.argv or "--version" in sys.argv:
        print_banner(__scriptname__, __version__)
        exit(0)
    args = parser.parse_args()

    do_help = not (not args.silent or args.format)
    if do_help:
        print_banner(__scriptname__, __version__)
    if args.list:
        print('\n'.join(ptodnes.datasources.list_datasources()))
        exit(0)
    if args.config:
        ConfigProvider().config_file = pathlib.Path(args.config)

    result = await ptodnes.process.process(loop, **args.__dict__)


    if result is None:
        exit(1)

    output = dataexporter.convert(result, args.format, very_verbose=args.very_verbose)

    if args.output is None:
        ptprint(output)
    else:
        try:
            with open(f"{args.output}.{args.format}", 'w') as output_file:
                output_file.write(output)
        except Exception:
            pass
            # parser.error(f"error when opening file {args.file}")