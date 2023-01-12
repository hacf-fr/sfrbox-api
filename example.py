"""Sample interation with SFRBox."""
from __future__ import annotations

import asyncio
import logging
import os

import httpx

from sfrbox_api.bridge import SFRBox


username: str = os.environ.get("SFRBOX_USERNAME", "admin")
password: str | None = os.environ.get("SFRBOX_PASSWORD")


async def main() -> None:
    """Main entry point."""
    logging.basicConfig(level=logging.DEBUG)
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.100.10", client=client)
        print(await box.system_get_info())
        print(await box.dsl_get_info())
        print(await box.wan_get_info())
        print(await box.ftth_get_info())

        if username and password:
            await box.authenticate(username=username, password=password)
            # await box.system_reboot()


if __name__ == "__main__":
    asyncio.run(main())
