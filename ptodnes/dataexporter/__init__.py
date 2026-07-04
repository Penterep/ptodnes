from argparse import Namespace

from ptodnes.DNS.dnsinfo import DNSInfo
from ptodnes.DNS.record import DNSRecord
from ptodnes.DNS.dns_record_dict import DNSRecordDict
from ptlibs import ptjsonlib, out_if
import yaml
import json
import dataclasses
import sys


def group_by_source(domain_data: DNSRecordDict) -> dict[str, dict[str, set[str]]]:
    grouped = {}
    for domain, records in domain_data.items():
        for record in records:
            for source in record.source:
                if not source:
                    continue
                source_group = grouped.setdefault(source, {"domains": set(), "ips": set()})
                source_group["domains"].add(domain)
                if record.type == "A" and record.value:
                    source_group["ips"].add(record.value)
    return grouped


def get_domain_bt(domain_data: DNSInfo, show_status: bool) -> str:
    if not show_status:
        return "TEXT"

    if domain_data.matches is True:
        return "OK"

    if domain_data.matches is False:
        return "WARNING"

    return "ERROR"


def serializer(x):
    """
    Serialize dataclass into `dict`
    :param x: dataclass
    :return: dataclass as dict or x
    """
    if dataclasses.is_dataclass(x):
        return dataclasses.asdict(x, dict_factory=DNSRecord.dict_factory)
    else:
        return x

class OdnesDumper(yaml.Dumper):
    """
    YAML serializer class
    """
    def represent_data(self, data):
        # Apply the serializer to the data before dumping it
        data = serializer(data)
        return super().represent_data(data)



def convert(domain_data: DNSRecordDict, args: Namespace, separator=';') -> str:
    """
    Convert domain data to output format
    :param domain_data: DNSRecordDict to convert
    :param args: args`
    :param separator: separator for csv output format
    :return:
    """
    output_format: str = args.format
    very_verbose: bool = args.very_verbose

    match output_format:
        case 'yaml':
            output = yaml.dump(dict(domain_data), Dumper=OdnesDumper)
        case 'json':
            output = json.dumps(domain_data, indent=2, default=serializer)
        case 'csv':
            output = "domain;type;value;last_seen;sources;verified\n"
            for domain, records in domain_data.items():
                if records:
                    for record in records:
                        output += f"{domain}{separator}"
                        output += f'{record.type}{separator}'
                        output += f"{record.value}{separator}"
                        output += f"{record.record_last_seen}{separator}"
                        output += f"{' '.join(record.source)}{separator}"
                        output += f"{record.verified}\n"
                else:
                    output += f"{domain}{separator * 5}\n"
        case 'ptjson':
            ptjson = ptjsonlib.PtJsonLib()
            if '-wa' in sys.argv or '--web-apps' in sys.argv:
                for domain, info in domain_data.items():
                    if info.is_vhost:
                        is_actual = any(x.verified for x in info.records)
                        vhost_node = ptjson.create_node_object('web_app',None, None, {'name':domain, 'availability': 'actual' if is_actual else 'historical'}, None, None, info.vulnerabilities)
                        ptjson.add_node(vhost_node)
            else:
                for domain, records in domain_data.items():
                    domain_node = ptjson.create_node_object('domain',None,None,{'name':domain})
                    ptjson.add_node(domain_node)
                    for record in records:
                        record_node = ptjson.create_node_object('dns_record', 'domain', domain_node.get('key'), serializer(record))
                        ptjson.add_node(record_node)
            ptjson.set_status('finished')
            output = ptjson.get_result_json()
        case 'verbose':
            output = '\n'
            for domain, records in domain_data.items():
                if False:
                    if not records:
                        output += f"{' ' * 2}NXDOMAIN\n"
                    for record in records:
                        output += f'{' ' * 2}{record.type}:\n'
                        output += f"{' ' * 4}Value: {record.value}\n"
                        output += f"{' ' * 4}Last seen: {record.record_last_seen}\n"
                        output += f"{' ' * 4}Verified: {record.verified}\n"
                        output += f"{' ' * 4}Source: {record.source}\n"
        case _:
            output = "\n"
            output += "===== Results =====\n\n"

            for source, values in sorted(group_by_source(domain_data).items()):
                if source == "DNS" and args.ip_address:
                    output += '\n'
                    continue
                output += out_if(f"{source}\n", bullet_type='INFO', colortext=True, condition=True)
                output += out_if("Domains\n", bullet_type='INFO', colortext=False, condition=bool(values["domains"]))
                for domain in sorted(values["domains"]):
                    bt = get_domain_bt(domain_data[domain], bool(args.query and args.ip_address))
                    output += out_if(f"{domain}\n", bullet_type=bt, colortext=False, condition=True, indent=4)

                if not args.ip_address:
                    output += out_if("IPs\n", bullet_type='INFO', colortext=False, condition=bool(values["ips"]))
                    for ip in sorted(values["ips"]):
                        output += out_if(f"{ip}\n", bullet_type='TEXT', colortext=False, condition=True, indent=4)

            output += '\n'

            # Print vhosts for domains present on tested IP
            if any(p.is_vhost and (p.matches or not args.query) for p in domain_data.values()):
                output += out_if("Web applications on tested IP\n", bullet_type="INFO", colortext=True, condition=True)
                for domain, info in domain_data.items():
                    output += out_if(f"{domain}\n", bullet_type="TEXT", colortext=True,
                                     condition=info.is_vhost and (info.matches or not args.query), indent=4)

                output += '\n'

            # Print vhosts for domains present on another IP
            if any(p.is_vhost and not p.matches for p in domain_data.values()) and args.query:
                output += out_if("Web applications on another IP\n", bullet_type="INFO", colortext=True, condition=True)
                for domain, info in domain_data.items():
                    if info.records:
                        for record in info.records:
                            if "DNS" in record.source:
                                output += out_if(f"{domain}    ({record.value})\n",
                                     bullet_type="TEXT", colortext=True, condition=info.is_vhost and not info.matches,
                                     indent=4)

                output += '\n'

            # Print old vhosts
            if any(p.is_vhost and p.vulnerabilities is not None and "PTV-WEB-MISCONF-OLDVHOST" in p.vulnerabilities for p in domain_data.values()):
                output += out_if("Non-deleted Web Applications on tested IP\n", bullet_type="INFO", colortext=True, condition=True)
                for domain, info in domain_data.items():
                    output += out_if(f"{domain}\n", bullet_type="TEXT", colortext=True,
                                     condition=info.is_vhost and
                                               info.vulnerabilities is not None and
                                               "PTV-WEB-MISCONF-OLDVHOST" in info.vulnerabilities,
                                     indent=4)

                output += '\n'

            # Print summary of results
            output += out_if("Summary\n", bullet_type='INFO', colortext=True, condition=True)
            for domain, records in domain_data.items():
                output += out_if(f"{domain}\n", bullet_type='TEXT', colortext=False, condition=True)
                if very_verbose:
                    output += out_if(f"Vhost found!\n",
                                         bullet_type='WARNING', colortext=True, condition=records.is_vhost, indent=2)
                    output += out_if(f"Vulnerabilities: {', '.join(records.vhost_hits[0].vulnerabilities) if records.vhost_hits else None}\n",
                                         bullet_type='VULN', colortext=True, condition=records.is_vhost, indent=4)
                    output += out_if(f"None\n",
                                         bullet_type='OK', colortext=True, condition=records.is_vhost and len(records.vhost_hits[0].vulnerabilities) == 0, indent=6)
                    for record in records:
                        if record.type == 'A':
                            output += out_if(f"IP: {record.value or 'Unknown'}, Last seen: {record.record_last_seen.date() if record.record_last_seen else "Unknown"}, \
Verified: {"Yes" if record.verified else "No"}\n",
                                         bullet_type='ADDITIONS', colortext=True, condition=very_verbose, indent=2)
                        elif record.type == 'CNAME':
                            output += out_if(
                                f"CNAME of: {record.value or 'Unknown'}, Last seen: {record.record_last_seen.date() if record.record_last_seen else "Unknown"}, \
Verified: {"Yes" if record.verified else "No"}\n",
                                bullet_type='ADDITIONS', colortext=True, condition=very_verbose, indent=2)

    return output
