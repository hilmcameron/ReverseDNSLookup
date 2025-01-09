#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import annotations

import socket
import logging
import asyncio
import argparse
import ipaddress
from functools import lru_cache
from typing import List, Optional, Protocol, Any, Type, Dict

import aiohttp

API_KEY = "ApiKey"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class IPValidator(Protocol):
    def is_valid_ip(self, ip: str) -> bool:
        ...


class ReverseLookup(Protocol):
    async def reverse_lookup(self, ip: str) -> Optional[str]:
        ...


class WebsitesOnServer(Protocol):
    async def get_websites_on_server(self, ip: str) -> List[str]:
        ...


class IPUtils(IPValidator, ReverseLookup, WebsitesOnServer):
    def __init__(self, session: Optional[aiohttp.ClientSession] = None) -> None:
        self.session = session

    async def setup(self) -> None:
        self.session = aiohttp.ClientSession()

    async def close(self) -> None:
        if self.session:
            await self.session.close()

    async def __aenter__(self) -> IPUtils:
        await self.setup()
        return self

    async def __aexit__(self, exc_type: Type[BaseException], exc_val: BaseException, exc_tb: Any) -> None:
        await self.close()

    def __repr__(self) -> str:
        return f"<IPUtils(session={self.session})>"

    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    @lru_cache(maxsize=128)
    async def reverse_lookup(ip: str) -> Optional[str]:
        loop = asyncio.get_event_loop()
        try:
            domain = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            return domain[0]
        except socket.herror:
            return None

    async def get_websites_on_server(self, ip: str) -> List[str]:
        if not self.session:
            raise RuntimeError("Session not initialized. Call setup() first.")
        url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey={API_KEY}&output=json"
        async with self.session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                if "response" in data and "domains" in data["response"]:
                    return data["response"]["domains"]
        return []

    @staticmethod
    def validate_ips(ips: List[str]) -> Dict[str, bool]:
        return {ip: IPUtils.is_valid_ip(ip) for ip in ips}


async def process_ip(ip_utils: IPUtils, ip: str, print_all: bool) -> None:
    if not IPUtils.is_valid_ip(ip):
        logging.error(f"Invalid IP address: {ip}")
        return

    domain = await IPUtils.reverse_lookup(ip)
    if domain:
        logging.info(f"IP: {ip}, Domain: {domain}")
    else:
        logging.warning(f"No domain found for IP: {ip}")
        return

    if print_all:
        websites = await ip_utils.get_websites_on_server(ip)
        if websites:
            logging.info("Other websites on the same server:")
            logging.info("\n".join(websites))
        else:
            logging.warning("No other websites found on the same server.")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Perform IP reverse lookup.")
    parser.add_argument("ips", nargs="+", help="IP address(es) to perform reverse lookup on.")
    parser.add_argument("--all", "-a", action="store_true", help="Print all other websites on the same server.")
    args = parser.parse_args()

    async with IPUtils() as ip_utils:
        await asyncio.gather(*(process_ip(ip_utils, ip, args.all) for ip in args.ips))


if __name__ == "__main__":
    asyncio.run(main())
