"""SFR Box bridge."""
from __future__ import annotations

import logging
from xml.etree.ElementTree import Element as XmlElement  # noqa: S405

import defusedxml.ElementTree as DefusedElementTree
import httpx

from sfrbox_api.helpers import compute_hash

from .exceptions import SFRBoxApiError
from .exceptions import SFRBoxAuthenticationError
from .exceptions import SFRBoxError
from .models import DslInfo
from .models import FtthInfo
from .models import SystemInfo
from .models import WanInfo


_LOGGER = logging.getLogger(__name__)


class SFRBox:
    """SFR Box bridge."""

    _token: str | None = None
    _username: str | None = None
    _password: str | None = None

    def __init__(self, *, ip: str, client: httpx.AsyncClient) -> None:
        """Initialise SFR Box bridge."""
        self._ip = ip
        self._client = client

    async def authenticate(self, *, username: str = "admin", password: str) -> None:
        """Initialise le token pour pouvoir accéder aux méthodes privées de l'API."""
        self._username = username
        self._password = password
        self._token = None
        await self._ensure_token()

    async def _ensure_token(self) -> str:
        if not self._token:
            self._token = await self._get_token()
        assert self._token  # noqa: S101
        return self._token

    async def _get_token(self) -> str | None:
        if not (self._username and self._password):
            raise SFRBoxAuthenticationError("Credentials not set")
        element = await self._send_get("auth", "getToken")
        if (method := element.get("method")) not in {"all", "passwd"}:
            raise SFRBoxAuthenticationError(
                f"Password authentication is not allowed, valid methods: `{method}`"
            )
        token = element.get("token")
        hash = compute_hash(token, self._username, self._password)
        element = await self._send_get("auth", "checkToken", token=token, hash=hash)
        return element.get("token")

    async def _send_get(self, namespace: str, method: str, **kwargs: str) -> XmlElement:
        params = httpx.QueryParams(method=f"{namespace}.{method}", **kwargs)
        response = await self._client.get(f"http://{self._ip}/api/1.0/", params=params)
        _LOGGER.debug(
            'HTTP Response: %s %s "%s %s %s" %s',
            response.request.method,
            response.url,
            response.http_version,
            response.status_code,
            response.reason_phrase,
            response.text,
        )
        response.raise_for_status()
        try:
            element: XmlElement = DefusedElementTree.fromstring(response.text)
        except Exception as exc:
            raise SFRBoxError(f"Failed to parse response: {response.text}") from exc
        stat = element.get("stat", "")
        if (
            stat == "fail"
            and (err := element.find("err")) is not None
            and (msg := err.get("msg"))
        ):
            raise SFRBoxApiError(f"Api call failed: {msg}")
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
