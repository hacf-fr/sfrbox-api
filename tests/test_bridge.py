"""Test cases for the __main__ module."""

import pathlib
import re
import time

import aiohttp
import pytest
from aioresponses import aioresponses

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


@pytest.mark.asyncio
async def test_authenticate(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=auth.getToken",
        body=_load_fixture("auth.getToken.xml"),
    )
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=auth.checkToken"
        "&token=afd1baa4cb261bfc08ec2dc0ade3b4"
        "&hash=3e89f9170f9e64e5132aa6f72a520ffd45f952f259872a60e9acde5dba45ff64"
        "88cc72099f52b8414e5b182b8e1c2b4b87863bd67b0134904adfe00ae6c6499e",
        body=_load_fixture("auth.checkToken.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        await box.authenticate(password="password")  # noqa: S106

        assert box._username == "admin"
        assert box._password == "password"  # noqa: S105
        assert box._token == "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105

        # Ensure subsequent calls return existing token
        mocked_responses.clear()
        assert await box._ensure_token() == "afd1baa4cb261bfc08ec2dc0ade3b4"


@pytest.mark.asyncio
async def test_authenticate_invalid_password(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=auth.getToken",
        body=_load_fixture("auth.getToken.xml"),
    )
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=auth.checkToken"
        "&token=afd1baa4cb261bfc08ec2dc0ade3b4"
        "&hash=3e89f9170f9e64e5132aa6f72a520ffd45f952f259872a60e9acde5dba45ff64"
        "2df17d326805a188a8446a7cf9372132d617925ea7130947e9bbefa2a5b5bb84",
        body=_load_fixture("fail.204.xml"),
    )

    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_authenticate_no_credentials() -> None:
    """It exits with a status code of zero."""
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxAuthenticationError, match="Credentials not set"
        ):
            await box._ensure_token()


@pytest.mark.asyncio
async def test_authenticate_method_not_allowed(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=auth.getToken",
        body=_load_fixture("auth.getToken.xml").replace('"all"', '"button"'),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxAuthenticationError,
            match="Password authentication is not allowed, valid methods: `button`",
        ):
            await box.authenticate(password="password")  # noqa: S106


@pytest.mark.asyncio
async def test_authenticate_method_not_allowed_domain(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://sfrbox.example.com/api/1.0/?method=auth.getToken",
        body=_load_fixture("auth.getToken.xml").replace('"all"', '"button"'),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="http://sfrbox.example.com", client=client)
        with pytest.raises(
            SFRBoxAuthenticationError,
            match="Password authentication is not allowed, valid methods: `button`",
        ):
            await box.authenticate(password="password")  # noqa: S106


@pytest.mark.asyncio
async def test_authenticate_method_not_allowed_domain_and_path(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://example.com/sfrbox/api/1.0/?method=auth.getToken",
        body=_load_fixture("auth.getToken.xml").replace('"all"', '"button"'),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="http://example.com/sfrbox", client=client)
        with pytest.raises(
            SFRBoxAuthenticationError,
            match="Password authentication is not allowed, valid methods: `button`",
        ):
            await box.authenticate(password="password")  # noqa: S106


@pytest.mark.asyncio
async def test_authenticate_method_not_allowed_https_and_domain(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "https://sfrbox.example.com/api/1.0/?method=auth.getToken",
        body=_load_fixture("auth.getToken.xml").replace('"all"', '"button"'),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="https://sfrbox.example.com", client=client)
        with pytest.raises(
            SFRBoxAuthenticationError,
            match="Password authentication is not allowed, valid methods: `button`",
        ):
            await box.authenticate(password="password")  # noqa: S106


@pytest.mark.asyncio
async def test_dsl_getinfo_3dcm020200r015(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=dsl.getInfo",
        body=_load_fixture("dsl.getInfo.3DCM020200r015.xml"),
    )
    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_dsl_getinfo(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=dsl.getInfo",
        body=_load_fixture("dsl.getInfo.xml"),
    )
    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_ftth_getinfo(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=ftth.getInfo",
        body=_load_fixture("ftth.getInfo.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.ftth_get_info()
        assert info == FtthInfo(status="down", wanfibre="out")


@pytest.mark.asyncio
async def test_ftth_getinfo_3dcm020200r015(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=ftth.getInfo",
        body=_load_fixture("ftth.getInfo.3DCM020200r015.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.ftth_get_info()
        assert info is None


@pytest.mark.asyncio
async def test_system_getinfo(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=system.getInfo",
        body=_load_fixture("system.getInfo.xml"),
    )
    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_system_getinfo_3_5_8(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=system.getInfo",
        body=_load_fixture("system.getInfo.3_5_8.xml"),
    )
    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_system_getinfo_3dcm020200r015(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=system.getInfo",
        body=_load_fixture("system.getInfo.3DCM020200r015.xml"),
    )
    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_system_getinfo_box10h_xbsp_1_6_14_1(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=system.getInfo",
        body=_load_fixture("system.getInfo.BOX10H-XbSP-1.6.14.1.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        info = await box.system_get_info()
        assert info == SystemInfo(
            product_id="BOX10H-SER-r0",
            mac_addr="6C:61:F4:xxxxxx",
            net_mode="router",
            net_infra="ftth",
            uptime=5334,
            version_mainfirmware="BOX10H-XbSP-1.6.14.1",
            version_rescuefirmware="BOX10H-XbSP-1.2.40",
            version_bootloader="U-Boot2019.07(09/22/2025-17:42:41+0200)50404p3@510198",
            version_dsldriver="",
            current_datetime="20251024160207",
            refclient="",
            idur="RQE9SIU",
            alimvoltage=0.0,
            temperature=48.5,
            serial_number="CS1A0530006xxxxxxx",
        )


@pytest.mark.asyncio
async def test_system_reboot(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.post(
        "http://192.168.0.1/api/1.0/?method=system.reboot&token=afd1baa4cb261bfc08ec2dc0ade3b4",
        body=_load_fixture("ok.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        await box.system_reboot()


@pytest.mark.asyncio
async def test_system_reboot_bad_auth(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.post(
        "http://192.168.0.1/api/1.0/?method=system.reboot&token=invalid_token",
        body=_load_fixture("fail.115.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "invalid_token"  # noqa: S105
        box._token_time = time.time()
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape("Api call failed: [115] Authentication needed"),
        ):
            await box.system_reboot()


@pytest.mark.asyncio
async def test_wan_getinfo(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wan.getInfo",
        body=_load_fixture("wan.getInfo.xml"),
    )
    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_wlan_getclientlist(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wlan.getClientList&token=afd1baa4cb261bfc08ec2dc0ade3b4",
        body=_load_fixture("wlan.getClientList.xml"),
    )
    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_wlan_getinfo(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wlan.getInfo&token=afd1baa4cb261bfc08ec2dc0ade3b4",
        body=_load_fixture("wlan.getInfo.xml"),
    )
    async with aiohttp.ClientSession() as client:
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


@pytest.mark.asyncio
async def test_wan_getinfo_fail(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wan.getInfo",
        body=_load_fixture("fail.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxApiError,
            match=re.escape(
                "Api call failed: [[code-erreur]] [message-erreur]"
            ),
        ):
            await box.wan_get_info()


@pytest.mark.asyncio
async def test_wan_getinfo_invalid_xml(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wan.getInfo", body="Invalid XML"
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxError, match="Failed to parse response: Invalid XML"
        ):
            await box.wan_get_info()


@pytest.mark.asyncio
async def test_wan_getinfo_incorrect_xml(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wan.getInfo",
        body="<incorrect_xml />",
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxError, match="Response was not ok: <incorrect_xml />"
        ):
            await box.wan_get_info()


@pytest.mark.asyncio
async def test_wan_getinfo_incorrect_namespace(
    mocked_responses: aioresponses,
) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wan.getInfo",
        body=_load_fixture("dsl.getInfo.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(
            SFRBoxError, match="Namespace wan not found in response"
        ):
            await box.wan_get_info()


@pytest.mark.asyncio
async def test_connect_timeout(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wan.getInfo",
        exception=aiohttp.ConnectionTimeoutError,
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(SFRBoxError):
            await box.wan_get_info()


@pytest.mark.asyncio
async def test_500_error(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.get(
        "http://192.168.0.1/api/1.0/?method=wan.getInfo",
        status=500,
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        with pytest.raises(SFRBoxError):
            await box.wan_get_info()


@pytest.mark.asyncio
async def test_enable_wifi(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.post(
        "http://192.168.0.1/api/1.0/?method=wlan.enable&token=afd1baa4cb261bfc08ec2dc0ade3b4",
        body=_load_fixture("ok.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        await box.wlan_enable()


@pytest.mark.asyncio
async def test_enable_wifi_bad_auth(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.post(
        "http://192.168.0.1/api/1.0/?method=wlan.enable&token=invalid_token",
        body=_load_fixture("fail.115.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "invalid_token"  # noqa: S105
        box._token_time = time.time()
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape("Api call failed: [115] Authentication needed"),
        ):
            await box.wlan_enable()


@pytest.mark.asyncio
async def test_disable_wifi(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.post(
        "http://192.168.0.1/api/1.0/?method=wlan.disable&token=afd1baa4cb261bfc08ec2dc0ade3b4",
        body=_load_fixture("ok.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        await box.wlan_disable()


@pytest.mark.asyncio
async def test_disable_wifi_bad_auth(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.post(
        "http://192.168.0.1/api/1.0/?method=wlan.disable&token=invalid_token",
        body=_load_fixture("fail.115.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "invalid_token"  # noqa: S105
        box._token_time = time.time()
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape("Api call failed: [115] Authentication needed"),
        ):
            await box.wlan_disable()


@pytest.mark.asyncio
async def test_restart_wifi(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.post(
        "http://192.168.0.1/api/1.0/?method=wlan.restart&token=afd1baa4cb261bfc08ec2dc0ade3b4",
        body=_load_fixture("ok.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "afd1baa4cb261bfc08ec2dc0ade3b4"  # noqa: S105
        box._token_time = time.time()
        await box.wlan_restart()


@pytest.mark.asyncio
async def test_restart_wifi_bad_auth(mocked_responses: aioresponses) -> None:
    """It exits with a status code of zero."""
    mocked_responses.post(
        "http://192.168.0.1/api/1.0/?method=wlan.restart&token=invalid_token",
        body=_load_fixture("fail.115.xml"),
    )
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.0.1", client=client)
        box._token = "invalid_token"  # noqa: S105
        box._token_time = time.time()
        with pytest.raises(
            SFRBoxAuthenticationError,
            match=re.escape("Api call failed: [115] Authentication needed"),
        ):
            await box.wlan_restart()
