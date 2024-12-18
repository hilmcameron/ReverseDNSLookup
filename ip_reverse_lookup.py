#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import annotations

import socket
import logging
import asyncio
import argparse
import ipaddress

from typing import List, Optional, Protocol
from functools import lru_cache

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
    def __init__(self) -> None:
        self.session: Optional[aiohttp.ClientSession] = None

    async def setup(self) -> None:
        self.session = aiohttp.ClientSession()

    async def close(self) -> None:
        if self.session:
            await self.session.close()

    def __aenter__(self) -> IPUtils:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.setup())
        return self

    def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.close())

    def __repr__(self):
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


async def main():
    parser = argparse.ArgumentParser(description="Perform IP reverse lookup.")
    parser.add_argument("ips", nargs="+", help="IP address(es) to perform reverse lookup on.")
    parser.add_argument("--all", "-a", action="store_true", help="Print all other websites on the same server.")
    args = parser.parse_args()

    async with IPUtils() as ip_utils:
        for ip in args.ips:
            if not ip_utils.is_valid_ip(ip):
                logging.error(f"Invalid IP address: {ip}")
                continue

            domain = await ip_utils.reverse_lookup(ip)
            if not domain:
                logging.warning(f"No domain found for IP: {ip}")
                continue

            logging.info(f"IP: {ip}, Domain: {domain}")

            if args.all:
                websites = await ip_utils.get_websites_on_server(ip)
                if websites:
                    logging.info("Other websites on the same server:")
                    logging.info("\n".join(websites))
                else:
                    logging.warning("No other websites found on the same server.")


if __name__ == "__main__":
    asyncio.run(main())
