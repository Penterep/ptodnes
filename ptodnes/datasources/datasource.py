from abc import ABCMeta, abstractmethod
from dataclasses import dataclass
from datetime import timezone, datetime
from typing import overload, Self, Any, Optional

from ptlibs.ptprinthelper import out_if, ptprint

from ptodnes.DNS.record import DNSRecord, SOARecord, MXRecord, CAARecord
from ptodnes.configprovider.configprovider import ConfigProvider


def date_from_iso(date: str | None):
    """
    Convert ISO date to datetime
    :param date: ISO date
    :return:
    """
    if date:
        return datetime.fromisoformat(date)
    else:
        return None


def date_from_utc(date: str | None) -> datetime | None:
    """
    Convert UTC timestamp to datetime
    :param date: UTC timestamp
    :return:
    """
    if date:
        return datetime.fromtimestamp(int(date), timezone.utc)
    else:
        return None

class DNSRecordGenerator:
    """
    DNSRecord factory class.
    Generates specific DNS records based on type provided.
    """
    def __new__(cls, *args, source, verified = False, **kwargs):
        """
        Create new DNSRecord
        :param args:
        :param source:
        :param verified:
        :param kwargs:
        """
        rtype = kwargs.get("type",'')
        kwargs['source'] = {source}
        match rtype:
            case 'SOA':
                return SOARecord(verified = verified, **kwargs)
            case 'MX':
                return MXRecord(verified = verified, **kwargs)
            case 'CAA':
                return CAARecord(verified = verified, **kwargs)
            case _:
                return DNSRecord(verified = verified, **kwargs)

@dataclass
class DatasourceObject:
    """
    Holds data returned from datasource.
    """
    domain: str
    DNSData: list[DNSRecord]

    def __contains__(self, item):
        return item in self.DNSData

    @overload
    def __eq__(self, other: Self):
        return self.domain == other.domain

    def __eq__(self, other: str):
        return self.domain == other

    def __hash__(self):
        return hash(self.domain)

    def __str__(self):
        return self.domain


class Datasource(metaclass=ABCMeta):
    """
    Abstract base class for all datasource.
    """

    loaded_datasource: dict[str, Self] = {}
    verbose: bool = True
    @property
    def config(self):
        return ConfigProvider().get_config(self.__class__.__name__)

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value: int):
        if value < 0: value=0
        self._timeout = value

    @property
    def retry(self):
        return self._retry

    @retry.setter
    def retry(self, value: int):
        if value<0: value=0
        self._retry = value

    @property
    def wordlists(self):
        return self._wordlists

    @wordlists.setter
    def wordlists(self, value: list):
        self._wordlists = value

    @property
    def qtype(self):
        return self._qtype

    @qtype.setter
    def qtype(self, value):
        self._qtype = value

    def __init__(self, **kwargs):
        self._wordlists: Optional[list] = None
        self._api_url: Optional[str]
        self._verbose: bool = Datasource.verbose
        self._verbose_level: int = 3
        self._timeout: int = 5
        self._retry: int = 5
        self._qtype: Optional[list] = None
        self._api_key: Optional[str] = None
        self._enabled: bool = True

    @abstractmethod
    def add_api_key(self, api_key: str):
        pass

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__()
        instance = cls()
        Datasource.loaded_datasource[cls.__name__.lower()] = instance

    def on_load(self):
        self.print_ok("Datasource loaded")

    @abstractmethod
    async def check_api_key(self):
        pass

    @abstractmethod
    async def search(self, domain: str):
        """
        Abstract method to be implemented by every indexer to search for domain information.

        :param domain: The domain to search for
        :return domain_info: `DomainInfo` object if domain is found, `None` otherwise
        """
        pass

    @abstractmethod
    async def reverse_search(self, IP: str):
        pass

    def _print_level(self, level):
        return self._verbose and self._verbose_level >= level
    def print_info(self, msg, *args, **kwargs):
        if self._print_level(level=3):
            ptprint(f"{self.__class__.__name__}: {msg}", "INFO", *args, **kwargs)
    def print_ok(self, msg, *args, **kwargs):
        ptprint(out_if(f"{self.__class__.__name__}: {msg}", "OK", self._print_level(3)), *args, **kwargs)
    def print_error(self, msg, *args, **kwargs):
        ptprint(out_if(f"{self.__class__.__name__}: {msg}", "ERROR", self._print_level(1)), *args, **kwargs)
    def print_warning(self, msg, *args, **kwargs):
        ptprint(out_if(f"{self.__class__.__name__}: {msg}", "WARNING", self._print_level(2)), *args, **kwargs)
    def set_verbose(self, verbose, *args, **kwargs):
        self._verbose = verbose
    def set_verbose_level(self, verbose_level):
        self._verbose_level = verbose_level