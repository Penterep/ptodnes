from ptodnes.DNS.record import DNSRecord
from ptodnes.DNS.dns_record_dict import DNSRecordDict
import ptodnes.datasources
from ptlibs import ptjsonlib, out_if
import yaml
import json
import dataclasses
import sys

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



def convert(domain_data: DNSRecordDict, output_format: str, separator=';', very_verbose: bool = False) -> str:
    """
    Convert domain data to output format
    :param domain_data: DNSRecordDict to convert
    :param output_format: output format string valid are `csv`, `json`, and `yaml`
    :param separator: separator for csv output format
    :return:
    """
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
                        vhost_node = ptjson.create_node_object('web_app',None, None, {'name':domain, 'availabilty': 'actual' if is_actual else 'historical'}, None, None, info.vulnerabilities)
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
            for datasource in ptodnes.datasources.datasources.values():
                datasource_items = domain_data.by_datasource(datasource)
                if datasource_items:
                    output += out_if(f"{datasource.__class__.__name__}\n", bullet_type='INFO', colortext=True, condition=True)
                    output += out_if(f"{'\n'.join([x for x in datasource_items.keys()])}\n\n", bullet_type='TEXT', colortext=False, condition=True)
            if any(p.is_vhost for p in domain_data.values()):
                output += out_if("Web Applications\n", bullet_type='INFO', colortext=True, condition=True)
                for domain, info in domain_data.items():
                    output += out_if(f"{domain}\n", bullet_type='TEXT', colortext=True, condition=info.is_vhost)
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