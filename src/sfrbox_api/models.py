"""SFR Box models."""
from dataclasses import dataclass


@dataclass
class DslInfo:
    linemode: str  # Mode du lien. (firmware >= 2.1.2)
    uptime: str  # Nombre de seconde depuis la montée du lien. (firmware >= 2.1.2)
    counter: str  # Nombre de connexion ADSL effectué. (firmware >= 2.1.2)
    crc: str  # Nombre d’erreur CRC. (firmware >= 2.1.2)
    status: str  # = (up|down). Status du lien.
    noise_down: str  # Marge de bruit flux descendant.
    noise_up: str  # Marge de bruit flux montant.
    attenuation_down: str  # Atténuation flux descendant.
    attenuation_up: str  # Atténuation flux montant.
    rate_down: str  # Débit flux descendant.
    rate_up: str  # Débit flux montant.
    line_status: str  # = (No Defect|Of Frame|Loss Of Signal|Loss Of Power|Loss Of Signal Quality|Unknown). Etat détaillé du lien. (firmware >= 3.3.2)
    training: str  # = (Idle|G.994 Training|G.992 Started|G.922 Channel Analysis|G.992 Message Exchange|G.993 Started|G.993 Channel Analysis|G.993 Message Exchange|Showtime|Unknown). Etat de négociation avec le DSLAM. (firmware >= 3.3.2)


@dataclass
class FtthInfo:
    status: str  # = (up|down). Etat du lien. (firmware >= 3.3.2)
    wanfibre: str  # = (in|out) Etat du port fibre par rapport au bridge wan0. (firmware >= 3.5.0)


@dataclass
class SystemInfo:
    product_id: str  # L’ID du produit: $(NB)-$(HARD)-$(HARD_VERSION).
    mac_addr: str  # L’adresse MAC de la neufbox.
    net_mode: str  # = (router|bridge).
    net_infra: str  # = (adsl|ftth|gprs). Connexion internet principale de la BOX.
    uptime: str  # Temps d’activité de la BOX en seconde.
    version_mainfirmware: str  # Version du firmware de la BOX: $(NB)-MAIN-R$(VERSION).
    version_rescuefirmware: str  #
    version_bootloader: str  #
    version_dsldriver: str  # (indisponible sur NB5) (firmware >= 2.1.2)
    current_datetime: str  # Date actuelle sous le format : "%Y%m%d%H%M". (firmware >= 3.2.0)
    refclient: str  # Référence client. (firmware >= 3.2.0)
    idur: str  # Identifiant unique réseau. (firmware >= 3.4.0)
    alimvoltage: str  # Tension de l’alimentation exprimé en mV. (firmware >= 3.5.0)
    temperature: str  # Température de la BOX exprimé en m°C. (firmware >= 3.5.0)
    serial_number: str  # Numéro de série de l’IAD. (firmware >= 4.0.0)


@dataclass
class WanInfo:
    status: str  # = (up|down). Status de la connexion internet.
    uptime: str  # Temps de connexion internet v4 ou v6 (suivant les cas)
    ip_addr: str  # Adresse IPv4 internet. (MAP-T inclus, peut être vide si Only sans conf MAP-T))
    infra: str  # = (adsl|ftth|gprs). Lien utilisé pour la connexion internet. (firmware >= 2.1.2)
    mode: str  # = (ftth/routed|adsl/routed|adsl/ppp|gprs/ppp). Mode de connexion internet.(firmware >= 3.3.2)
    infra6: str  # = (Tunnel|Dual|Native|Only|unknown). Lien utilisé pour la connexion internetIPv6. (firmware >= 3.4)
    status6: str  # = (up|down). Status de la connexion internet IPv6. (firmware >= 3.4)
    uptime6: str  # Temps de connexion internet IPv6. (firmware >= 3.4)
    ipv6_addr: str  # Adresse IPv6 globale de la box. (firmware >= 3.4)
