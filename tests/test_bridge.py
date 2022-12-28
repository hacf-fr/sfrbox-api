"""Test cases for the __main__ module."""
import httpx
import pathlib
import pytest
import respx

from sfrbox_api.bridge import SFRBox
from sfrbox_api.models import DslInfo, FtthInfo, SystemInfo, WanInfo

def _load_fixture(filename:str) -> str:
    return pathlib.Path(__file__).parent.joinpath("fixtures", filename).read_text()

@respx.mock
@pytest.mark.asyncio
async def test_bridge_dsl() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=dsl.getInfo").respond(text=_load_fixture("dsl.xml"))
    async with httpx.AsyncClient() as client:

        box = SFRBox(ip="192.168.0.1", client=client)
        dsl = await box.dsl_getInfo()
        assert dsl == DslInfo(linemode='ADSL2+', uptime='450796', counter='16', crc='0', status='up', noise_down='5.8', noise_up='6.0', attenuation_down='28.5', attenuation_up='20.8', rate_down='5549', rate_up='187', line_status='No Defect', training='Showtime')

@respx.mock
@pytest.mark.asyncio
async def test_bridge_ftth() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=ftth.getInfo").respond(text=_load_fixture("ftth.xml"))
    async with httpx.AsyncClient() as client:

        box = SFRBox(ip="192.168.0.1", client=client)
        dsl = await box.ftth_getInfo()
        assert dsl == FtthInfo(status='down', wanfibre='out')

@respx.mock
@pytest.mark.asyncio
async def test_bridge_system() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=system.getInfo").respond(text=_load_fixture("system.xml"))
    async with httpx.AsyncClient() as client:

        box = SFRBox(ip="192.168.0.1", client=client)
        dsl = await box.system_getInfo()
        print(dsl)
        assert dsl == SystemInfo(product_id='NB6VAC-FXC-r0', mac_addr='e4:5d:51:00:11:22', net_mode='router', net_infra='adsl', uptime='2353575', version_mainfirmware='NB6VAC-MAIN-R4.0.44k', version_rescuefirmware='NB6VAC-MAIN-R4.0.44k', version_bootloader='NB6VAC-BOOTLOADER-R4.0.8', version_dsldriver='NB6VAC-XDSL-A2pv6F039p', current_datetime='202212282233', refclient='', idur='RP3P85K', alimvoltage='12251', temperature='27560', serial_number='XU1001001001001001')

@respx.mock
@pytest.mark.asyncio
async def test_bridge_wan() -> None:
    """It exits with a status code of zero."""
    respx.get("http://192.168.0.1/api/1.0/?method=wan.getInfo").respond(text=_load_fixture("wan.xml"))
    async with httpx.AsyncClient() as client:

        box = SFRBox(ip="192.168.0.1", client=client)
        dsl = await box.wan_getInfo()
        assert dsl == WanInfo(status='up', uptime='2353338', ip_addr='88.219.146.196', infra='adsl', mode='adsl/routed', infra6='', status6='down', uptime6='', ipv6_addr='')
