"""
MOLE - Managed Obfuscated Link Environment
A VPN tunnel manager with port forwarding and torrent client integration
"""

__version__ = "0.4.0"
__author__ = "MOLE Contributors"

# Defer imports to avoid circular dependencies
def get_mole_class():
    from .mole import Mole
    return Mole

def get_config_class():
    from .config import Config
    return Config
