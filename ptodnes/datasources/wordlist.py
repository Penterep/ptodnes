import asyncio
import re

import punycode

from ptodnes.DNS.dns_record_dict import DNSRecordDict
from ptodnes.DNS.odnesdns import OdnesDNS
from ptodnes.datasources.datasource import Datasource, DatasourceObject, DNSRecordGenerator
from ptodnes.progress import ProgressManager

# One DNS label: 1-63 chars, letters/digits/hyphen, no hyphen at start or end.
# Checked per label, so long TLDs (.technology) and IDN TLDs (xn--p1ai) are accepted.
_LABEL_RE = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

DEFAULT_QTYPES = ['A', 'AAAA', 'CNAME']


def is_valid_hostname(name: str) -> bool:
    if len(name) > 253:
        return False
    labels = name.split('.')
    return len(labels) >= 2 and all(_LABEL_RE.match(label) for label in labels)


def _read_words(path: str) -> list[str]:
    """Read the wordlist synchronously (called in a worker thread)."""
    with open(path, 'r', encoding='utf-8', errors='replace') as file:
        # strip() also removes '\r' from wordlists with Windows line endings
        return [line.strip() for line in file if not line.lstrip().startswith('#')]


class Wordlist(Datasource):

    def __init__(self, api_key: str = ''):
        super().__init__()
        wordlists_cfg = self.config.get("wordlists", [])
        self._enabled = self.config.get('enabled', True)
        self.__wordlists = [wordlists_cfg] if isinstance(wordlists_cfg, str) else list(wordlists_cfg)

    async def check_api_key(self):
        pass

    def add_api_key(self, api_key: str = None):
        pass

    async def search(self, domain: str):
        if not self._enabled:
            return []
        wordlists = self._wordlists or self.__wordlists  # CLI (-w) has priority over config
        self.print_info("Started wordlist search")

        res = DNSRecordDict()
        res.extend(self._build_candidates(domain, await self.read_wordlists(wordlists)))
        if not res:
            return []

        dns = OdnesDNS()
        qtypes = self._qtype or DEFAULT_QTYPES
        progress = ProgressManager()

        async def query_type(qtype: str):
            with progress.task(f"{domain} {qtype}", total=len(res), verbose=self._verbose) as bar:
                await dns.query(res, qtype=qtype, on_progress=bar.advance)

        await asyncio.gather(*(query_type(qtype) for qtype in qtypes))
        self.print_info(f"DNS queries for {len(res)} candidates done")

        res.filter_untrusted()
        return res.as_list()

    def _build_candidates(self, domain: str, words: list[str]) -> list[DatasourceObject]:
        candidates = []
        # dict.fromkeys removes duplicates and keeps order
        for word in dict.fromkeys(words):
            subdomain = f"{word}.{domain}" if word else domain
            try:
                subdomain = punycode.convert(subdomain, True)
            except Exception:
                continue
            if not is_valid_hostname(subdomain):
                continue
            candidates.append(DatasourceObject(domain=subdomain, DNSData=[
                DNSRecordGenerator(source=self.__class__.__name__, type='<NONE>', verified=False,
                                   value="<EMPTY>", ttl=None, record_last_seen=None)]))
        return candidates

    async def reverse_search(self, IP: str):
        if not self._enabled:
            return []
        if self._barier:
            self.print_warning("IP address lookup is not supported.")
            self._barier = False
        return []

    async def read_wordlists(self, wordlists: list[str]) -> list[str]:
        words: list[str] = []
        for wordlist in wordlists:
            self.print_info(f"Reading wordlist {wordlist}")
            try:
                # Reading line by line through aiofiles sends each line through the thread pool
                # (500k lines ~ 80 s). One read in a single thread takes milliseconds.
                words.extend(await asyncio.to_thread(_read_words, wordlist))
            except PermissionError:
                self.print_error(f"Permissions denied for '{wordlist}'")
            except FileNotFoundError:
                self.print_error(f"Wordlist '{wordlist}' not found")
            except IsADirectoryError:
                self.print_error(f"Wordlist '{wordlist}' is not a file")
            except OSError as e:
                self.print_error(f"Cannot read wordlist '{wordlist}': {e}")
        self.print_info(f"Loaded {len(words)} words")
        return words
