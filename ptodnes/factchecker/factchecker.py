import asyncio
from collections.abc import AsyncGenerator
import re
from dataclasses import dataclass, field
from typing import Iterable, List, TYPE_CHECKING, Self

import aiohttp

from ptodnes.DNS.dnsinfo import DNSInfo
from ptodnes.DNS.record import DNSRecord

if TYPE_CHECKING:
    from ptodnes.DNS.dns_record_dict import DNSRecordDict


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str | None) -> str | None:
    if not html:
        return None
    m = _TITLE_RE.search(html)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()[:200] or None


async def _is_tcp_open(host: str, port: int, timeout: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host=host, port=port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _fetch_ip_with_host(
    session: aiohttp.ClientSession,
    scheme: str,
    ip: str,
    host_header: str,
    timeout: int,
) -> tuple[int | None, str | None]:
    url = f"{scheme}://{ip}/"
    try:
        async with session.get(
            url,
            headers={"Host": host_header},
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            status = resp.status
            try:
                text = await resp.text(errors="ignore")
            except Exception:
                text = None
            return status, _extract_title(text)
    except Exception:
        return None, None


@dataclass(frozen=True)
class VhostHit:
    scheme: str          # "http" | "https"
    ip: str
    status: int | None
    title: str | None
    baseline_status: int | None
    baseline_title: str | None
    dns_current: bool
    vulnerabilities: List[str] = field(default_factory=list)

"""
    def __str__(self):
        return self.domain
    
    def __hash__(self):
        return hash(self.domain)
"""

class VhostFactChecker:
    """
    Checks whether domains behave as distinct vhosts (web apps) on a given IP.
    Baseline is built by querying the IP with a fictional Host header.
    Comparison is strictly (status_code, <title>).
    """
    __create_key = object()

    def __init__(self, create_key: object, ip: str, *, timeout: int = 5, baseline_host: str = "www.example.com"):
        if create_key is not VhostFactChecker.__create_key:
            raise TypeError("Use the 'create' class method to instantiate this class.")
        self._ip = ip
        self._timeout = max(0, int(timeout))
        self._baseline_host = baseline_host
        self._schemes = []
    
    @classmethod
    async def create(cls, ip: str, *, timeout: int = 5, baseline_host: str = "www.example.com") -> Self:
        self = cls(cls.__create_key, ip, timeout=timeout, baseline_host=baseline_host)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async for scheme in self._detect_schemes():
                self._schemes.append(scheme)
                base_st, base_title = await _fetch_ip_with_host(
                    session=session,
                    scheme=scheme,
                    ip=self._ip,
                    host_header=self._baseline_host,
                    timeout=self._timeout,
                )
                if base_st is not None:
                    self.__setattr__(scheme, (base_st, base_title))
        return self
    
    def _baseline(self, scheme: str) -> tuple[int | None, str | None]:
        return getattr(self, scheme, (None, None))



    async def _detect_schemes(self) -> AsyncGenerator[str, None]:
        http_open = await _is_tcp_open(self._ip, 80, self._timeout)
        https_open = await _is_tcp_open(self._ip, 443, self._timeout)
        if http_open:
            yield "http"
        if https_open:
            yield "https"
        return
    
    async def find_vhosts(
        self,
        info: DNSInfo
    ):
        for record in info.records:
            if record.type == 'A':
                if record.value != self._ip:
                    continue
                hits = await self._enumerate_vhost(info, record)
                if hits:
                    if not info.vhost_hits:
                        info.vhost_hits = hits
                    info.vhost_hits.extend(hits)
                    info.is_vhost = True
                    return
        
    
    async def _enumerate_vhost(
        self,
        info: DNSInfo,
        record: DNSRecord | None = None,
    ) -> list[VhostHit] | None:
        connector = aiohttp.TCPConnector(ssl=False)
        hits: List[VhostHit] = []
        async with aiohttp.ClientSession(connector=connector) as session:
            for scheme in self._schemes:
                st, title = await _fetch_ip_with_host(
                    session=session,
                    scheme=scheme,
                    ip=self._ip,
                    host_header=info.domain,
                    timeout=self._timeout,
                )
                base_st, base_title = self._baseline(scheme)
                if st is not None and (st, title) != (base_st, base_title):
                    vulns: List[str] = []
                    if record and not record.verified:
                        vulns.append("PTV-WEB-MISCONF-OLDVHOST")
                        info.add_vuln("PTV-WEB-MISCONF-OLDVHOST")
                    hits.append(
                            VhostHit(
                                scheme=scheme,
                                ip=self._ip,
                                status=st,
                                title=title,
                                baseline_status=base_st,
                                baseline_title=base_title,
                                dns_current=record.verified if record else False,
                                vulnerabilities=vulns,
                            )
                        )
        return hits if hits else None