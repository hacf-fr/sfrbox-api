"""SFR Box bridge."""
from __future__ import annotations

import xml.etree.ElementTree as ET

import httpx

from .models import DslInfo
from .models import FtthInfo
from .models import SystemInfo
from .models import WanInfo


class SFRBox:
    """SFR Box bridge."""

    def __init__(self, *, ip: str, client: httpx.AsyncClient) -> None:
        """Initialise SFR Box bridge."""
        self._ip = ip
        self._client = client

    async def _send_get(self, method: str, **kwargs: str) -> ET.Element:
        params = httpx.QueryParams(method=method, **kwargs)
        response = await self._client.get(f"http://{self._ip}/api/1.0/", params=params)
        element = ET.fromstring(response.text)
        stat = element.get("stat", "")
        if stat == "fail":
            err = element.find("err")
            assert err
            raise Exception(f"Query failed: {err.get('msg')}")
        if stat != "ok":
            raise Exception(f"Response was not ok: {stat}")
        result = element.find(method.split(".")[0])
        assert result is not None
        return result

    async def dsl_getInfo(self) -> DslInfo:
        xml_response = await self._send_get("dsl.getInfo")
        return DslInfo(**xml_response.attrib)

    async def ftth_getInfo(self) -> FtthInfo:
        xml_response = await self._send_get("ftth.getInfo")
        return FtthInfo(**xml_response.attrib)

    async def system_getInfo(self) -> SystemInfo:
        xml_response = await self._send_get("system.getInfo")
        return SystemInfo(**xml_response.attrib)

    async def wan_getInfo(self) -> WanInfo:
        xml_response = await self._send_get("wan.getInfo")
        return WanInfo(**xml_response.attrib)
