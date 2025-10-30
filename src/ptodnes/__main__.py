import asyncio
import pathlib
from argparse import ArgumentParser
import sys
import os
import ptodnes
import ptodnes.datasources
import ptodnes.dataexporter
from ptodnes import dataexporter
from ptodnes.configprovider.configprovider import ConfigProvider
from ptlibs.ptprinthelper import help_print, print_banner
import importlib.metadata



__version__ = importlib.metadata.version(__package__)
__scriptname__ = os.path.basename(sys.argv[0])


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
            ["-c", "--csv", "", "Output in CSV format"],
            ["-C", "--config", "<config>", "Path to config file (default ~/ptodnes.toml)"],
            ["-d", "--domain", "<domain ...>", "Domains to search for"],
            ["-D", "--datasource", "<datasource ...>", "Datasources to browse"],
            ["-e", "--exclude-unverified", "", "Exclude unverified records"],
            ["-j", "--json", "", "Output in JSON format"],
            ["-l", "--list", "", "List available datasources"],
            ["-n", "--nonxdomain", "", "Filter results with no DNS data"],
            ["-o", "--output", "<file_prefix>", "Save results to files (format specification required)"],
            ["-p", "--ptjson", "", "Output in ptJSONlib format"],
            ["-q", "--query", "", "Query domains against DNS servers"],
            ["-r", "--retry", "<count>", "Number of attempts (default:5)"],
            ["-t", "--type", "<type ...>", "Types of DNS records to search for"],
            ["-T", "--timeout", "<timeout>", "Datasource connection timeout (in seconds, default:5)"],
            ["-v", "--version", "", "Print version and exit"],
            ["-V", "--verbose", "<1|2|3|4>", "Set verbosity level (1=ERROR, 2=WARNING, 3=INFO, 4=DEBUG)"],
            ["-w", "--wordlist", "<wordlist ...>", "Path to wordlist(s) for wordlist search"],
            ["-y", "--yaml", "", "Output in YAML format"],
        ]
        }]

async def main(loop):
    if sys.platform != 'win32':
        ptodnes.add_signal_handlers()
    parser = ArgumentParser(add_help=False)
    parser.add_argument("-l", "--list", help="list available datasources", action="store_true", default=False)
    parser.add_argument("-d",
                        "--domain",
                        help="domain to search for",
                        nargs='+',
                        required=('-l' not in sys.argv and '--list' not in sys.argv),
                        type=str)
    parser.add_argument("-D",
                        "--datasource",
                        nargs='+',
                        help="Datasource to search",
                        metavar="DATASOURCE",
                        choices=ptodnes.datasources.names,
                        default="ANY",
                        type=str)
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
    parser.add_argument("-o", "--output", help="save results to files", type=str)
    parser.add_argument("-n", "--nonxdomain", help="disable output of NXDOMAIN", action="store_true", default=False)
    parser.add_argument("-V", "--verbose", help="verbosity level (1=ERROR, 2=WARNING, 3=INFO, 4=DEBUG)", type=int, default=3)
    parser.add_argument("-v", "--version", help="print version and exit", action="store_true", default=False)
    parser.add_argument("-r", "--retry", help="number of attempts", default=5, type=int)
    parser.add_argument("-T", "--timeout", help="timeout (in seconds)", default=5, type=int)
    parser.add_argument("-q", "--query", help="query domains against DNS servers", action="store_true", default=False, required=('-e' in sys.argv or '--exclude-unverified' in sys.argv))
    parser.add_argument("-e", "--exclude-unverified", help="exclude unverified records", action="store_true", default=False)
    format_parser = parser.add_mutually_exclusive_group(required=('-o' in sys.argv or '--output' in sys.argv))
    format_parser.add_argument("-j", "--json", help="output in JSON format", action="store_const", const="json", dest="format")
    format_parser.add_argument("-y", "--yaml", help="output in YAML format", action="store_const", const="yaml", dest="format")
    format_parser.add_argument("-c", "--csv", help="output in CSV format", action="store_const", const="csv", dest="format")
    format_parser.add_argument("-p", "--ptjson", help="output in ptJSONlib format", action="store_const", const="ptjson",
                               dest="format")

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
        print('\n'.join(ptodnes.datasources.names))
        exit(0)
    if args.config:
        ConfigProvider().config_file = pathlib.Path(args.config)

    result = await ptodnes.process(loop, args.domain, args.datasource, args.type, args.nonxdomain, args.query, args.exclude_unverified, args.format, args.silent, args.verbose, args.timeout, args.retry, args.wordlist)


    if result is None:
        exit(1)

    output = dataexporter.convert(result, args.format)

    if args.output is None:
        print(output)
    else:
        try:
            with open(f"{args.output}.{args.format}", 'w') as output_file:
                output_file.write(output)
        except Exception:
            pass
            # parser.error(f"error when opening file {args.file}")

def __main__():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(main(loop))
    finally:
        loop.close()


if __name__ == "__main__":
    __main__()
