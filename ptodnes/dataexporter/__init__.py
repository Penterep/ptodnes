from ptodnes.DNS.record import DNSRecord
from ptodnes.DNS.dns_record_dict import DNSRecordDict
from ptlibs import ptjsonlib, out_if
import yaml
import json
import dataclasses

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
            output += out_if("Summary\n", bullet_type='INFO', colortext=True, condition=True)
            for domain, records in domain_data.items():
                output += out_if(f"{domain}\n", bullet_type='TEXT', colortext=False, condition=True)
                if very_verbose:
                    for record in records:
                        output += out_if(f"Last seen: {record.record_last_seen.date() or "Unknown"}, \
Verified: {"Yes" if record.verified else "No"}, Type: {record.type or 'Unknown'}, \
Value: {record.value or 'Unknown'}\n",
                                         bullet_type='ADDITIONS', colortext=True, condition=very_verbose, indent=2)
    return output
