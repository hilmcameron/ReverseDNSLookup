#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import annotations

import socket
import logging
import asyncio
import argparse
import ipaddress
from functools import lru_cache
from typing import List, Optional, Dict, Any, Type

import aiohttp

API_KEY = "ApiKey"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class IPUtils:
    def __init__(self, session: Optional[aiohttp.ClientSession] = None) -> None:
        self.session = session or aiohttp.ClientSession()

    async def close(self) -> None:
        """Ensure session is closed when exiting."""
        if self.session:
            await self.session.close()

    async def __aenter__(self) -> IPUtils:
        return self

    async def __aexit__(self, exc_type: Type[BaseException], exc_val: BaseException, exc_tb: Any) -> None:
        await self.close()

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
        try:
            return await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyaddr, ip)
        except socket.herror:
            return None

    async def get_websites_on_server(self, ip: str) -> List[str]:
        """Fetch websites hosted on the same server as the IP."""
        url = f"https://api.viewdns.info/reverseip/?host={ip}&apikey={API_KEY}&output=json"
        async with self.session.get(url) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("response", {}).get("domains", [])
        return []

    @staticmethod
    def validate_ips(ips: List[str]) -> Dict[str, bool]:
        """Validate a list of IPs."""
        return {ip: IPUtils.is_valid_ip(ip) for ip in ips}


async def process_ip(ip_utils: IPUtils, ip: str, print_all: bool) -> None:
    """Process each IP: validate, perform reverse lookup, and optionally list websites on server."""
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
    """Main function to handle argument parsing and start IP processing."""
    parser = argparse.ArgumentParser(description="Perform IP reverse lookup.")
    parser.add_argument("ips", nargs="+", help="IP address(es) to perform reverse lookup on.")
    parser.add_argument("--all", "-a", action="store_true", help="Print all other websites on the same server.")
    args = parser.parse_args()

    async with IPUtils() as ip_utils:
        await asyncio.gather(*(process_ip(ip_utils, ip, args.all) for ip in args.ips))


if __name__ == "__main__":
    asyncio.run(main())
