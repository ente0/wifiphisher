#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#pylint: skip-file
import os

dir_of_executable = os.path.dirname(__file__)
path_to_project_root = os.path.abspath(
    os.path.join(dir_of_executable, '../../wifiphisher'))
dir_of_data = path_to_project_root + '/data/'

# Basic configuration
DEV = 0
DEAUTH_EXTENSION = "deauth"
LURE10_EXTENSION = "lure10"
WPSPBC = "wpspbc"
KNOWN_BEACONS_EXTENSION = "knownbeacons"
HANDSHAKE_VALIDATE_EXTENSION = "handshakeverify"
DEFAULT_EXTENSIONS = [DEAUTH_EXTENSION]
EXTENSIONS_LOADPATH = "wifiphisher.extensions."
PORT = 8080
SSL_PORT = 443
CHANNEL = 6
ALL_2G_CHANNELS = range(1, 14)
WEBSITE = "https://wifiphisher.org"
PUBLIC_DNS = "8.8.8.8"
PEM = dir_of_data + 'cert/server.pem'
PHISHING_PAGES_DIR = dir_of_data + "phishing-pages/"
SCENARIO_HTML_DIR = "html/"
LOGOS_DIR = dir_of_data + "logos/"
LOCS_DIR = dir_of_data + "locs/"
MAC_PREFIX_FILE = dir_of_data + "wifiphisher-mac-prefixes"
KNOWN_WLANS_FILE = dir_of_data + "wifiphisher-known-open-wlans"
POST_VALUE_PREFIX = "wfphshr"
phishing_pages_dir="/usr/share/wifiphisher/phishing-pages"

# ---- Network config ----
# NOTE: These are defaults and may be overridden at runtime by
# accesspoint.py when NetHunter mode is enabled.
# Use get_network_gw_ip() for current value in other modules.
NETWORK_IP = "10.0.0.0"
NETWORK_MASK = "255.255.255.0"
NETWORK_GW_IP = "10.0.0.1"
DHCP_LEASE = "10.0.0.2,10.0.0.100,12h"

WIFI_BROADCAST = "ff:ff:ff:ff:ff:ff"
WIFI_INVALID = "00:00:00:00:00:00"
WIFI_IPV6MCAST1 = "33:33:00:"
WIFI_IPV6MCAST2 = "33:33:ff:"
WIFI_SPANNINGTREE = "01:80:c2:00:00:00"
WIFI_MULTICAST = "01:00:5e:"
NON_CLIENT_ADDRESSES = set([
    WIFI_BROADCAST, WIFI_INVALID, WIFI_MULTICAST, WIFI_IPV6MCAST1,
    WIFI_IPV6MCAST2, WIFI_SPANNINGTREE, None
])
DEFAULT_OUI = '00:00:00'
LINES_OUTPUT = 3
DN = open(os.devnull, 'w')
INTERFERING_PROCS = [
    "wpa_action", "wpa_supplicant", "wpa_cli", "dhclient", "ifplugd", "dhcdbd",
    "dhcpcd", "udhcpc", "avahi-autoipd", "avahi-daemon", "wlassistant",
    "wifibox", "NetworkManager", "knetworkmanager"
]
NEW_YEAR = "01-01"
BIRTHDAY = "01-05"

# Modes of operation
OP_MODE1 = 0x1
OP_MODE2 = 0x2
OP_MODE3 = 0x3
OP_MODE4 = 0x4
OP_MODE5 = 0x5
OP_MODE6 = 0x6
OP_MODE7 = 0x7
OP_MODE8 = 0x8
# NetHunter mode: AP via Android hotspot
OP_MODE_NETHUNTER = 0x10

AP_RATES = "\x0c\x12\x18\x24\x30\x48\x60\x6c"

# Console colors
W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray
T = '\033[93m'  # tan

# Logging configurations
LOG_LEVEL = 'INFO'
LOG_FILEPATH = 'wifiphisher.log'
LOGGING_CONFIG = {
    'version': 1,
    'handlers': {
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': LOG_LEVEL,
            'formatter': 'detailed',
            'filename': LOG_FILEPATH,
            'backupCount': 3,
        },
    },
    'formatters': {
        'detailed': {
            'format': '%(asctime)s - %(name) 32s - %(levelname)s - %(message)s'
        },
    },
    'root': {
        'level': 'DEBUG',
        'handlers': [
            'file',
        ],
    },
    "loggers": {},
    'disable_existing_loggers': False
}

# NM DBus Marcos
NM_APP_PATH = 'org.freedesktop.NetworkManager'
NM_MANAGER_OBJ_PATH = '/org/freedesktop/NetworkManager'
NM_MANAGER_INTERFACE_PATH = 'org.freedesktop.NetworkManager'
NM_DEV_INTERFACE_PATH = 'org.freedesktop.NetworkManager.Device'

# Phishinghttp
VALID_POST_CONTENT_TYPE = "application/x-www-form-urlencoded"

# TUI
MAIN_TUI_ATTRS = 'version essid channel ap_iface em phishinghttp args'
AP_SEL_ATTRS = 'interface mac_matcher network_manager args'

# Fourway handshake extension
CONST_A = "Pairwise key expansion"

# Rogue AP related
DENY_MACS_PATH = '/tmp/hostapd.deny'

# Known Beacons
KB_INTERVAL = 20
KB_BUCKET_SIZE = 60
KB_BEACON_CAP = 0x2105
