"""SFR Box bridge."""
from __future__ import annotations

from xml.etree.ElementTree import Element as XmlElement  # noqa: S405

import httpx
from defusedxml.ElementTree import fromstring as xml_element_from_string

from .exceptions import SFRBoxError
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

    async def _send_get(self, namespace: str, method: str, **kwargs: str) -> XmlElement:
        params = httpx.QueryParams(method=f"{namespace}.{method}", **kwargs)
        response = await self._client.get(f"http://{self._ip}/api/1.0/", params=params)
        response.raise_for_status()
        try:
            element: XmlElement = xml_element_from_string(response.text)
        except Exception as exc:
            raise SFRBoxError(f"Failed to parse response: {response.text}") from exc
        stat = element.get("stat", "")
        if (
            stat == "fail"
            and (err := element.find("err")) is not None
            and (msg := err.get("msg"))
        ):
            raise SFRBoxError(f"Query failed: {msg}")
        if stat != "ok":
            raise SFRBoxError(f"Response was not ok: {response.text}")
        result = element.find(namespace)
        if result is None:
            raise SFRBoxError(
                f"Namespace {namespace} not found in response: {response.text}"
            )
        return result

    async def dsl_get_info(self) -> DslInfo:
        """Renvoie les informations sur le lien ADSL."""
        xml_response = await self._send_get("dsl", "getInfo")
        return DslInfo(**xml_response.attrib)  # type: ignore[arg-type]

    async def ftth_get_info(self) -> FtthInfo:
        """Renvoie les informations sur le lien FTTH."""
        xml_response = await self._send_get("ftth", "getInfo")
        return FtthInfo(**xml_response.attrib)

    async def system_get_info(self) -> SystemInfo:
        """Renvoie les informations sur le lien FTTH."""
        xml_response = await self._send_get("system", "getInfo")
        return SystemInfo(**xml_response.attrib)  # type: ignore[arg-type]

    async def wan_get_info(self) -> WanInfo:
        """Renvoie les informations génériques sur la connexion internet."""
        xml_response = await self._send_get("wan", "getInfo")
        return WanInfo(**xml_response.attrib)  # type: ignore[arg-type]
