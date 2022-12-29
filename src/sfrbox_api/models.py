"""SFR Box models."""
from typing import Optional

from pydantic import validator
from pydantic.dataclasses import dataclass


def _empty_to_none(v: str) -> Optional[str]:
    return None if v == "" else v


@dataclass
class DslInfo:
    """Informations sur le lien ADSL."""

    linemode: str
    """Mode du lien.
    (firmware >= 2.1.2)"""
    uptime: int
    """Nombre de seconde depuis la montée du lien.

    (firmware >= 2.1.2)"""
    counter: int
    """Nombre de connexion ADSL effectué.

    (firmware >= 2.1.2)"""
    crc: int
    """Nombre d'erreur CRC.

    (firmware >= 2.1.2)"""
    status: str
    """Status du lien.

    = (up|down)"""
    noise_down: float
    """Marge de bruit flux descendant."""
    noise_up: float
    """Marge de bruit flux montant."""
    attenuation_down: float
    """Atténuation flux descendant."""
    attenuation_up: float
    """Atténuation flux montant."""
    rate_down: int
    """Débit flux descendant."""
    rate_up: int
    """Débit flux montant."""
    line_status: str
    """Etat détaillé du lien.

    = (No Defect|Of Frame|Loss Of Signal|Loss Of Power|Loss Of Signal Quality|Unknown)
    (firmware >= 3.3.2)"""
    training: str
    """Etat de négociation avec le DSLAM.

    = (Idle|G.994 Training|G.992 Started|G.922 Channel Analysis|G.992 Message Exchange|
    G.993 Started|G.993 Channel Analysis|G.993 Message Exchange|Showtime|Unknown)

    (firmware >= 3.3.2)"""


@dataclass
class FtthInfo:
    """Informations sur le lien FTTH."""

    status: str
    """Etat du lien.

    = (up|down)

    (firmware >= 3.3.2)"""
    wanfibre: str
    """Etat du port fibre par rapport au bridge wan0.

    = (in|out)

    (firmware >= 3.5.0)"""


@dataclass
class SystemInfo:
    """Informations système."""

    product_id: str
    """L'ID du produit: $(NB)-$(HARD)-$(HARD_VERSION)."""
    mac_addr: str
    """L'adresse MAC de la neufbox."""
    net_mode: str
    """= (router|bridge)."""
    net_infra: str
    """Connexion internet principale de la BOX.

    = (adsl|ftth|gprs)"""
    uptime: int
    """Temps d'activité de la BOX en seconde."""
    version_mainfirmware: str
    """Version du firmware de la BOX: $(NB)-MAIN-R$(VERSION)."""
    version_rescuefirmware: str
    version_bootloader: str
    version_dsldriver: str
    """(indisponible sur NB5)

    (firmware >= 2.1.2)"""
    current_datetime: str
    """Date actuelle sous le format : "%Y%m%d%H%M".

    (firmware >= 3.2.0)"""
    refclient: str
    """Référence client.

    (firmware >= 3.2.0)"""
    idur: str
    """Identifiant unique réseau.

    (firmware >= 3.4.0)"""
    alimvoltage: int
    """Tension de l'alimentation exprimé en mV.

    (firmware >= 3.5.0)"""
    temperature: int
    """Température de la BOX exprimé en m°C.

    (firmware >= 3.5.0)"""
    serial_number: str
    """Numéro de série de l'IAD.

    (firmware >= 4.0.0)"""


@dataclass
class WanInfo:
    """Informations génériques sur la connexion internet."""

    # validators
    _empty_to_none = validator("uptime6", pre=True, allow_reuse=True)(_empty_to_none)

    status: str
    """Status de la connexion internet.

    = (up|down)"""
    uptime: int
    """Temps de connexion internet v4 ou v6 (suivant les cas)"""
    ip_addr: str
    """Adresse IPv4 internet.

    (MAP-T inclus, peut être vide si Only sans conf MAP-T)"""
    infra: str
    """Lien utilisé pour la connexion internet.

    = (adsl|ftth|gprs)

    (firmware >= 2.1.2)"""
    mode: str
    """Mode de connexion internet.

    = (ftth/routed|adsl/routed|adsl/ppp|gprs/ppp)

    (firmware >= 3.3.2)"""
    infra6: str
    """Lien utilisé pour la connexion internetIPv6.

    = (Tunnel|Dual|Native|Only|unknown)

    (firmware >= 3.4)"""
    status6: str
    """Status de la connexion internet IPv6.

    = (up|down)

    (firmware >= 3.4)"""
    uptime6: Optional[int]
    """Temps de connexion internet IPv6.

    (firmware >= 3.4)"""
    ipv6_addr: str
    """Adresse IPv6 globale de la box.

    (firmware >= 3.4)"""
