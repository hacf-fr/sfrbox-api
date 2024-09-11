"""Test cases for the __main__ module."""

import pathlib
import re
import time

import httpx
import pytest
import respx

from sfrbox_api.bridge import SFRBox
from sfrbox_api.exceptions import SFRBoxApiError
from sfrbox_api.exceptions import SFRBoxAuthenticationError
from sfrbox_api.exceptions import SFRBoxError
from sfrbox_api.models import DslInfo
from sfrbox_api.models import FtthInfo
from sfrbox_api.models import SystemInfo
from sfrbox_api.models import WanInfo
from sfrbox_api.models import WlanClient
from sfrbox_api.models import WlanClientList
from sfrbox_api.models import WlanInfo
from sfrbox_api.models import WlanWl0Info


def _load_fixture(filename: str) -> str:
    return (
        pathlib.Path(__file__).parent.joinpath("fixtures", filename).read_text()
    )


@respx.mock
@pytest.mark.asyncio
async def test_authenticate() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=auth.getToken").respond(
        text=_load_fixture("auth.getToken.xml")
    )
    respx.get(
        "http://192.168.0.1/api/1.0/?method=auth.checkToken"
        "&token=afd1baa4cb261bfc08ec2dc0ade3b4"
        "&hash=3e89f9170f9e64e5132aa6f72a520ffd45f952f259872a60e9acde5dba45ff64"
        "88cc72099f52b8414e5b182b8e1c2b4b87863bd67b0134904adfe00ae6c6499e"
    ).respond(text=_load_fixture("auth.checkToken.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        await box.authenticate(password="password")  # noqa: S106

        assert box._username == "admin"
        assert box._password == "password"  # noqa: S105
        assert box._token == "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105

        # Ensure subsequent calls return existing token
        respx.clear()
        assert await box._ensure_token() == "afd1baa4cb261bfc08ec2dc0ade3b4"


@respx.mock
@pytest.mark.asyncio
async def test_authenticate_invalid_password() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=auth.getToken").respond(
        text=_load_fixture("auth.getToken.xml")
    )
    respx.get(
        "http://192.168.0.1/api/1.0/?method=auth.checkToken"
        "&token=afd1baa4cb261bfc08ec2dc0ade3b4"
        "&hash=3e89f9170f9e64e5132aa6f72a520ffd45f952f259872a60e9acde5dba45ff64"
        "2df17d326805a188a8446a7cf9372132d617925ea7130947e9bbefa2a5b5bb84"
    ).respond(text=_load_fixture("fail.204.xml"))

    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "previous_token"  # noqa: S105
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape(
                "Api call failed: [204] Invalid login and/or password"
            ),
        ):
            await box.authenticate(password="invalid_password")  # noqa: S106
    assert box._username == "admin"
    assert box._password == "invalid_password"  # noqa: S105
    assert box._token is None


@respx.mock
@pytest.mark.asyncio
async def test_authenticate_no_credentials() -> None:
    """It exits with a status code of zero."""
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxAuthenticationError, match="Credentials not set"
        ):
            await box._ensure_token()


@respx.mock
@pytest.mark.asyncio
async def test_authenticate_method_not_allowed() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=auth.getToken").respond(
        text=_load_fixture("auth.getToken.xml").replace('"all"', '"button"')
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxAuthenticationError,
            match="Password authentication is not allowed, valid methods: `button`",
        ):
            await box.authenticate(password="password")  # noqa: S106


@respx.mock
@pytest.mark.asyncio
async def test_dsl_getinfo_3dcm020200r015() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=dsl.getInfo").respond(
        text=_load_fixture("dsl.getInfo.3DCM020200r015.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.dsl_get_info()
        assert info == DslInfo(
            linemode="G.DMT",
            uptime=4857,
            counter=1,
            crc=0,
            status="up",
            noise_down=4.5,
            noise_up=4.2,
            attenuation_down=3.2,
            attenuation_up=5.2,
            rate_down=8000,
            rate_up=800,
            line_status=None,
            training=None,
        )


@respx.mock
@pytest.mark.asyncio
async def test_dsl_getinfo() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=dsl.getInfo").respond(
        text=_load_fixture("dsl.getInfo.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.dsl_get_info()
        assert info == DslInfo(
            linemode="ADSL2+",
            uptime=450796,
            counter=16,
            crc=0,
            status="up",
            noise_down=5.8,
            noise_up=6.0,
            attenuation_down=28.5,
            attenuation_up=20.8,
            rate_down=5549,
            rate_up=187,
            line_status="No Defect",
            training="Showtime",
        )


@respx.mock
@pytest.mark.asyncio
async def test_ftth_getinfo() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=ftth.getInfo").respond(
        text=_load_fixture("ftth.getInfo.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.ftth_get_info()
        assert info == FtthInfo(status="down", wanfibre="out")


@respx.mock
@pytest.mark.asyncio
async def test_ftth_getinfo_3dcm020200r015() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=ftth.getInfo").respond(
        text=_load_fixture("ftth.getInfo.3DCM020200r015.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.ftth_get_info()
        assert info is None


@respx.mock
@pytest.mark.asyncio
async def test_system_getinfo() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=system.getInfo").respond(
        text=_load_fixture("system.getInfo.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.system_get_info()
        assert info == SystemInfo(
            product_id="NB6VAC-FXC-r0",
            mac_addr="e4:5d:51:00:11:22",
            net_mode="router",
            net_infra="adsl",
            uptime=2353575,
            version_mainfirmware="NB6VAC-MAIN-R4.0.44k",
            version_rescuefirmware="NB6VAC-MAIN-R4.0.44k",
            version_bootloader="NB6VAC-BOOTLOADER-R4.0.8",
            version_dsldriver="NB6VAC-XDSL-A2pv6F039p",
            current_datetime="202212282233",
            refclient="",
            idur="RP3P85K",
            alimvoltage=12251,
            temperature=27560,
            serial_number="XU1001001001001001",
        )


@respx.mock
@pytest.mark.asyncio
async def test_system_getinfo_3_5_8() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=system.getInfo").respond(
        text=_load_fixture("system.getInfo.3_5_8.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.system_get_info()
        assert info == SystemInfo(
            product_id="NB6V-SER-r0",
            mac_addr="e4:5d:51:00:11:22",
            net_mode="router",
            net_infra="adsl",
            uptime=762312,
            version_mainfirmware="NB6V-MAIN-R3.5.8",
            version_rescuefirmware="NB6V-MAIN-R3.4.5",
            version_bootloader="NB6V-BOOTLOADER-R3.3.2",
            version_dsldriver="NB6V-XDSL-A2pv6F038m",
            current_datetime="202302031201",
            refclient="",
            idur="RH7AA27",
            alimvoltage=12214,
            temperature=44699,
            serial_number=None,
        )


@respx.mock
@pytest.mark.asyncio
async def test_system_getinfo_3dcm020200r015() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=system.getInfo").respond(
        text=_load_fixture("system.getInfo.3DCM020200r015.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.system_get_info()
        assert info == SystemInfo(
            product_id="ALGD1-UBE-r0",
            mac_addr="***hidden***",
            net_mode="router",
            net_infra="fttb",
            uptime=1563441,
            version_mainfirmware="3DCM020200r015",
            version_rescuefirmware="3DCM020200r015",
            version_bootloader="3.00",
            version_dsldriver="",
            current_datetime="20240905130854",
            refclient="",
            idur="RNCUAOL",
            alimvoltage=12251,
            temperature=57.5,
            serial_number="MU1B01140006020043",
        )


@respx.mock
@pytest.mark.asyncio
async def test_system_reboot() -> None:
    """It exits with a status code of zero."""
    respx.post(
        "http://192.168.0.1/api/1.0/?method=system.reboot&token=afd1baa4cb261bfc08ec2dc0ade3b4"
    ).respond(text=_load_fixture("ok.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        await box.system_reboot()


@respx.mock
@pytest.mark.asyncio
async def test_system_reboot_bad_auth() -> None:
    """It exits with a status code of zero."""
    respx.post(
        "http://192.168.0.1/api/1.0/?method=system.reboot&token=invalid_token"
    ).respond(text=_load_fixture("fail.115.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "invalid_token"  # noqa: S105
        box._token_time = time.time()
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape("Api call failed: [115] Authentication needed"),
        ):
            await box.system_reboot()


@respx.mock
@pytest.mark.asyncio
async def test_wan_getinfo() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=wan.getInfo").respond(
        text=_load_fixture("wan.getInfo.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.wan_get_info()
        assert info == WanInfo(
            status="up",
            uptime=2353338,
            ip_addr="88.219.146.196",
            infra="adsl",
            mode="adsl/routed",
            infra6="",
            status6="down",
            uptime6=None,
            ipv6_addr="",
        )


@respx.mock
@pytest.mark.asyncio
async def test_wlan_getclientlist() -> None:
    """It exits with a status code of zero."""
    respx.get(
        "http://192.168.0.1/api/1.0/?method=wlan.getClientList&token=afd1baa4cb261bfc08ec2dc0ade3b4"
    ).respond(text=_load_fixture("wlan.getClientList.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        info = await box.wlan_get_client_list()
        assert info == WlanClientList(
            clients=[
                WlanClient(
                    mac_addr="01:02:03:04:05:06", ip_addr="192.168.1.23"
                ),
                WlanClient(
                    mac_addr="06:07:08:09:10:11", ip_addr="192.168.1.24"
                ),
            ]
        )


@respx.mock
@pytest.mark.asyncio
async def test_wlan_getinfo() -> None:
    """It exits with a status code of zero."""
    respx.get(
        "http://192.168.0.1/api/1.0/?method=wlan.getInfo&token=afd1baa4cb261bfc08ec2dc0ade3b4"
    ).respond(text=_load_fixture("wlan.getInfo.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        info = await box.wlan_get_info()
        assert info == WlanInfo(
            active="on",
            channel="11",
            mode="11ng",
            mac_filtering="off",
            wl0=WlanWl0Info(
                ssid="NEUF_0060",
                enc="WPA-PSK",
                keytype="ascii",
                wpakey="thazcynshag4knahadza",
                wepkey="",
            ),
        )


@respx.mock
@pytest.mark.asyncio
async def test_wan_getinfo_fail() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=wan.getInfo").respond(
        text=_load_fixture("fail.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxApiError,
            match=re.escape(
                "Api call failed: [[code-erreur]] [message-erreur]"
            ),
        ):
            await box.wan_get_info()


@respx.mock
@pytest.mark.asyncio
async def test_wan_getinfo_invalid_xml() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=wan.getInfo").respond(
        text="Invalid XML"
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxError, match="Failed to parse response: Invalid XML"
        ):
            await box.wan_get_info()


@respx.mock
@pytest.mark.asyncio
async def test_wan_getinfo_incorrect_xml() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=wan.getInfo").respond(
        text="<incorrect_xml />"
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxError, match="Response was not ok: <incorrect_xml />"
        ):
            await box.wan_get_info()


@respx.mock
@pytest.mark.asyncio
async def test_wan_getinfo_incorrect_namespace() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=wan.getInfo").respond(
        text=_load_fixture("dsl.getInfo.xml")
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxError, match="Namespace wan not found in response"
        ):
            await box.wan_get_info()


@respx.mock
@pytest.mark.asyncio
async def test_connect_timeout() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=wan.getInfo").mock(
        side_effect=httpx.ConnectTimeout
    )
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(SFRBoxError):
            await box.wan_get_info()


@respx.mock
@pytest.mark.asyncio
async def test_500_error() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=wan.getInfo").respond(500)
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(SFRBoxError):
            await box.wan_get_info()


@respx.mock
@pytest.mark.asyncio
async def test_enable_wifi() -> None:
    """It exits with a status code of zero."""
    respx.post(
        "http://192.168.0.1/api/1.0/?method=wlan.enable&token=afd1baa4cb261bfc08ec2dc0ade3b4"
    ).respond(text=_load_fixture("ok.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        await box.wlan_enable()


@respx.mock
@pytest.mark.asyncio
async def test_enable_wifi_bad_auth() -> None:
    """It exits with a status code of zero."""
    respx.post(
        "http://192.168.0.1/api/1.0/?method=wlan.enable&token=invalid_token"
    ).respond(text=_load_fixture("fail.115.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "invalid_token"  # noqa: S105
        box._token_time = time.time()
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape("Api call failed: [115] Authentication needed"),
        ):
            await box.wlan_enable()


@respx.mock
@pytest.mark.asyncio
async def test_disable_wifi() -> None:
    """It exits with a status code of zero."""
    respx.post(
        "http://192.168.0.1/api/1.0/?method=wlan.disable&token=afd1baa4cb261bfc08ec2dc0ade3b4"
    ).respond(text=_load_fixture("ok.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        await box.wlan_disable()


@respx.mock
@pytest.mark.asyncio
async def test_disable_wifi_bad_auth() -> None:
    """It exits with a status code of zero."""
    respx.post(
        "http://192.168.0.1/api/1.0/?method=wlan.disable&token=invalid_token"
    ).respond(text=_load_fixture("fail.115.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "invalid_token"  # noqa: S105
        box._token_time = time.time()
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape("Api call failed: [115] Authentication needed"),
        ):
            await box.wlan_disable()


@respx.mock
@pytest.mark.asyncio
async def test_restart_wifi() -> None:
    """It exits with a status code of zero."""
    respx.post(
        "http://192.168.0.1/api/1.0/?method=wlan.restart&token=afd1baa4cb261bfc08ec2dc0ade3b4"
    ).respond(text=_load_fixture("ok.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        await box.wlan_restart()


@respx.mock
@pytest.mark.asyncio
async def test_restart_wifi_bad_auth() -> None:
    """It exits with a status code of zero."""
    respx.post(
        "http://192.168.0.1/api/1.0/?method=wlan.restart&token=invalid_token"
    ).respond(text=_load_fixture("fail.115.xml"))
    async with httpx.AsyncClient() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "invalid_token"  # noqa: S105
        box._token_time = time.time()
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape("Api call failed: [115] Authentication needed"),
        ):
            await box.wlan_restart()
