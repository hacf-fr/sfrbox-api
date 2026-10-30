# SFR Box API

[![PyPI](https://img.shields.io/pypi/v/sfrbox-api.svg)][pypi_]
[![Python Version](https://img.shields.io/pypi/pyversions/sfrbox-api)][python version]
[![License](https://img.shields.io/pypi/l/sfrbox-api)][license]

[![Tests](https://github.com/hacf-fr/sfrbox-api/workflows/Tests/badge.svg)][tests]
[![Codecov](https://codecov.io/gh/hacf-fr/sfrbox-api/branch/main/graph/badge.svg)][codecov]

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)][pre-commit]
[![ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)][ruff]

[pypi_]: https://pypi.org/project/sfrbox-api/
[python version]: https://pypi.org/project/sfrbox-api
[tests]: https://github.com/hacf-fr/sfrbox-api/actions?workflow=Tests
[codecov]: https://app.codecov.io/gh/hacf-fr/sfrbox-api
[pre-commit]: https://github.com/pre-commit/pre-commit
[ruff]: https://github.com/astral-sh/ruff

## What is this?

`sfrbox-api` is an async Python client for the local XML API exposed by SFR
boxes (`http://<box>/api/1.0/?method=...`). It is used by Home Assistant's
[SFR Box integration][ha-sfr-box].

Home Assistant users don't need to install it: it ships with Home Assistant.

## Installation

```console
$ pip install sfrbox-api
```

Python 3.11+ is required.

## Usage

```python
import asyncio

import aiohttp

from sfrbox_api.bridge import SFRBox


async def main() -> None:
    async with aiohttp.ClientSession() as client:
        box = SFRBox(ip="192.168.1.1", client=client)

        # Public methods don't need credentials.
        print(await box.system_get_info())
        print(await box.wan_get_info())

        # Private methods need the box's admin password.
        await box.authenticate(password="...")
        print(await box.wlan_get_info())


asyncio.run(main())
```

`ip` accepts an IPv4 or IPv6 address, a host name, or a full
`http://`/`https://` URL. The token used by private methods is requested on
first use and renewed automatically.

See [`example.py`](example.py) for a runnable script.

### Supported methods

Each `SFRBox` method maps to one API call and returns a dataclass from
`sfrbox_api.models`.

| Method                         | API call                  | Authentication |
| ------------------------------ | ------------------------- | -------------- |
| `dsl_get_info()`               | `dsl.getInfo`             | no             |
| `ftth_get_info()`              | `ftth.getInfo`            | no             |
| `system_get_info()`            | `system.getInfo`          | no             |
| `wan_get_info()`               | `wan.getInfo`             | no             |
| `system_reboot()`              | `system.reboot`           | yes            |
| `voip_get_info()`              | `voip.getInfo`            | yes            |
| `voip_get_call_history_list()` | `voip.getCallhistoryList` | yes            |
| `wlan_get_info()`              | `wlan.getInfo`            | yes            |
| `wlan_get_client_list()`       | `wlan.getClientList`      | yes            |
| `wlan_enable()`                | `wlan.enable`             | yes            |
| `wlan_disable()`               | `wlan.disable`            | yes            |
| `wlan_restart()`               | `wlan.restart`            | yes            |

The `*_get_info()` methods return `None` when the box has no data for that
section, for example `dsl_get_info()` on a fibre box.

### Errors

All errors raised by the library subclass
`sfrbox_api.exceptions.SFRBoxError`:

- `SFRBoxAuthenticationError`: missing or wrong credentials, or password
  authentication disabled on the box.
- `SFRBoxApiError`: the box rejected the call.
- `SFRBoxError`: HTTP errors raised by aiohttp (`aiohttp.ClientError`) and
  unexpected responses.

## Contributing

Contributions are very welcome. To learn more, see the [Contributor Guide].

## License

Distributed under the terms of the [MIT license][license],
_SFR Box API_ is free and open source software.

## Issues

If you encounter any problems,
please [file an issue] along with a detailed description.

[ha-sfr-box]: https://www.home-assistant.io/integrations/sfr_box/
[file an issue]: https://github.com/hacf-fr/sfrbox-api/issues
[license]: https://github.com/hacf-fr/sfrbox-api/blob/main/LICENSE
[contributor guide]: https://github.com/hacf-fr/sfrbox-api/blob/main/CONTRIBUTING.md
