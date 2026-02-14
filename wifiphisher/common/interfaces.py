"""
This module handles all the interface related operations.
Patched for NetHunter: pyric/dbus are optional.
"""

import random
import re
import os
import subprocess
import logging
from collections import defaultdict
import wifiphisher.common.constants as constants

logger = logging.getLogger("wifiphisher.interfaces")

# Conditional imports — pyric and dbus may not be available on Android
try:
    import pyric
    import pyric.pyw as pyw
    HAS_PYRIC = True
except ImportError:
    HAS_PYRIC = False
    logger.warning("pyric not available — using Android fallback")

try:
    import dbus
    HAS_DBUS = True
except ImportError:
    HAS_DBUS = False


class InvalidInterfaceError(Exception):
    def __init__(self, interface_name, mode=None):
        message = "The provided interface \"{0}\" is invalid!".format(
            interface_name)
        if mode:
            message += "Interface {0} doesn't support {1} mode".format(
                interface_name, mode)
        Exception.__init__(self, message)


class InvalidMacAddressError(Exception):
    def __init__(self, mac_address):
        message = "The provided MAC address {0} is invalid".format(mac_address)
        Exception.__init__(self, message)


class InvalidValueError(Exception):
    def __init__(self, value, correct_value_type):
        value_type = type(value)
        message = ("Expected value type to be {0} while got {1}.".format(
            correct_value_type, value_type))
        Exception.__init__(self, message)


class InterfaceCantBeFoundError(Exception):
    def __init__(self, interface_modes):
        monitor_mode = interface_modes[0]
        ap_mode = interface_modes[1]
        message = "Failed to find an interface with "
        if monitor_mode:
            message += "monitor"
        elif ap_mode:
            message += "AP"
        message += " mode"
        Exception.__init__(self, message)


class InterfaceManagedByNetworkManagerError(Exception):
    def __init__(self, interface_name):
        message = (
            "Interface \"{0}\" is controlled by NetworkManager."
            "You need to manually set the devices that should be ignored by "
            "NetworkManager using the keyfile plugin (unmanaged-directive)."
            .format(interface_name))
        Exception.__init__(self, message)


# ---- Android fallback helpers ----

def _android_get_interfaces():
    """Get wireless interface list using /sys or ip command."""
    interfaces = []
    # Method 1: /sys/class/net
    try:
        for iface in os.listdir('/sys/class/net'):
            wireless_dir = '/sys/class/net/%s/wireless' % iface
            phy_dir = '/sys/class/net/%s/phy80211' % iface
            if os.path.isdir(wireless_dir) or os.path.isdir(phy_dir):
                interfaces.append(iface)
    except OSError:
        pass

    # Method 2: iw dev
    if not interfaces:
        try:
            output = subprocess.check_output(
                ['iw', 'dev'], stderr=subprocess.PIPE
            ).decode('utf-8', errors='replace')
            for line in output.splitlines():
                m = re.match(r'\s+Interface\s+(\S+)', line)
                if m:
                    interfaces.append(m.group(1))
        except (subprocess.CalledProcessError, OSError):
            pass

    return interfaces


def _android_get_mac(iface):
    """Get MAC address of interface."""
    try:
        path = '/sys/class/net/%s/address' % iface
        with open(path) as f:
            return f.read().strip()
    except (IOError, OSError):
        pass
    try:
        output = subprocess.check_output(
            ['ip', 'link', 'show', iface], stderr=subprocess.PIPE
        ).decode('utf-8', errors='replace')
        m = re.search(r'link/ether\s+([\da-f:]+)', output, re.I)
        if m:
            return m.group(1)
    except (subprocess.CalledProcessError, OSError):
        pass
    return '00:00:00:00:00:00'


class NetworkAdapter(object):
    """Represents a network interface"""

    def __init__(self, name, card_obj, mac_address):
        self._name = name
        self._has_ap_mode = False
        self._has_monitor_mode = False
        self._is_managed_by_nm = False
        self._card = card_obj
        self._original_mac_address = mac_address
        self._current_mac_address = mac_address

    @property
    def name(self):
        return self._name

    @property
    def is_managed_by_nm(self):
        return self._is_managed_by_nm

    @is_managed_by_nm.setter
    def is_managed_by_nm(self, value):
        if isinstance(value, bool):
            self._is_managed_by_nm = value
        else:
            raise InvalidValueError(value, bool)

    @property
    def has_ap_mode(self):
        return self._has_ap_mode

    @has_ap_mode.setter
    def has_ap_mode(self, value):
        if isinstance(value, bool):
            self._has_ap_mode = value
        else:
            raise InvalidValueError(value, bool)

    @property
    def has_monitor_mode(self):
        return self._has_monitor_mode

    @has_monitor_mode.setter
    def has_monitor_mode(self, value):
        if isinstance(value, bool):
            self._has_monitor_mode = value
        else:
            raise InvalidValueError(value, bool)

    @property
    def card(self):
        return self._card

    @property
    def mac_address(self):
        return self._current_mac_address

    @mac_address.setter
    def mac_address(self, value):
        self._current_mac_address = value

    @property
    def original_mac_address(self):
        return self._original_mac_address


class NetworkManager(object):
    """Handles all management for the interfaces."""

    def __init__(self):
        self._name_to_object = dict()
        self._active = set()
        self._exclude_shutdown = set()
        self._internet_access_enable = False
        self._vifs_add = set()
        self._nethunter_mode = False

    @property
    def internet_access_enable(self):
        return self._internet_access_enable

    @internet_access_enable.setter
    def internet_access_enable(self, value):
        if isinstance(value, bool):
            self._internet_access_enable = value
        else:
            raise InvalidValueError(value, bool)

    def enable_nethunter_mode(self):
        """Enable NetHunter mode - relaxed interface management."""
        self._nethunter_mode = True

    def is_interface_valid(self, interface_name, mode=None):
        if self._nethunter_mode:
            # In NetHunter mode, accept any interface
            self._active.add(interface_name)
            return True

        try:
            interface_adapter = self._name_to_object[interface_name]
        except KeyError:
            if mode == "internet":
                return True
            else:
                raise InvalidInterfaceError(interface_name)

        if mode == "internet" or mode == "WPS":
            self._exclude_shutdown.add(interface_name)
        if mode != "internet" and interface_adapter.is_managed_by_nm \
                and self.internet_access_enable:
            raise InterfaceManagedByNetworkManagerError(interface_name)
        if mode == "monitor" and not interface_adapter.has_monitor_mode:
            raise InvalidInterfaceError(interface_name, mode)
        elif mode == "AP" and not interface_adapter.has_ap_mode:
            raise InvalidInterfaceError(interface_name, mode)

        if interface_name in self._active:
            raise InvalidInterfaceError(interface_name)

        self._active.add(interface_name)
        return True

    def up_interface(self, interface_name):
        if self._nethunter_mode:
            try:
                subprocess.call(['ip', 'link', 'set', interface_name, 'up'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError:
                pass
            return

        card = self._name_to_object[interface_name].card
        pyw.up(card)

    def down_interface(self, interface_name):
        if self._nethunter_mode:
            try:
                subprocess.call(['ip', 'link', 'set', interface_name, 'down'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError:
                pass
            return

        card = self._name_to_object[interface_name].card
        pyw.down(card)

    def set_interface_mac(self, interface_name, mac_address):
        if self._nethunter_mode:
            # On Android, MAC changing may not work but don't crash
            self.down_interface(interface_name)
            try:
                subprocess.call(
                    ['ip', 'link', 'set', interface_name, 'address', mac_address],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError:
                pass
            if interface_name in self._name_to_object:
                self._name_to_object[interface_name].mac_address = mac_address
            return

        self._name_to_object[interface_name].mac_address = mac_address
        card = self._name_to_object[interface_name].card
        self.set_interface_mode(interface_name, "managed")
        self.down_interface(interface_name)
        try:
            pyw.macset(card, mac_address)
        except pyric.error:
            raise InvalidMacAddressError(mac_address)

    def get_interface_mac(self, interface_name):
        if self._nethunter_mode:
            if interface_name in self._name_to_object:
                return self._name_to_object[interface_name].mac_address
            return _android_get_mac(interface_name)

        return self._name_to_object[interface_name].mac_address

    def set_interface_mac_random(self, interface_name):
        new_mac_address = generate_random_address()
        self.set_interface_mac(interface_name, new_mac_address)

    def set_interface_mode(self, interface_name, mode):
        if self._nethunter_mode:
            # On Android, mode switching via iw often fails; skip silently
            if HAS_PYRIC and interface_name in self._name_to_object:
                try:
                    card = self._name_to_object[interface_name].card
                    pyw.down(card)
                    pyw.modeset(card, mode)
                except Exception:
                    pass
            return

        card = self._name_to_object[interface_name].card
        self.down_interface(interface_name)
        pyw.modeset(card, mode)

    def get_interface(self, has_ap_mode=False, has_monitor_mode=False):
        if self._nethunter_mode:
            # Return first available wireless interface not already active
            for iface in self._name_to_object:
                if iface not in self._active:
                    self._active.add(iface)
                    return iface
            raise InterfaceCantBeFoundError((has_monitor_mode, has_ap_mode))

        possible_adapters = list()
        for interface, adapter in self._name_to_object.items():
            if (interface not in self._active) and (
                    adapter not in possible_adapters):
                if (adapter.has_ap_mode == has_ap_mode
                        and adapter.has_monitor_mode == has_monitor_mode):
                    possible_adapters.insert(0, adapter)
                elif has_ap_mode and adapter.has_ap_mode:
                    possible_adapters.append(adapter)
                elif has_monitor_mode and adapter.has_monitor_mode:
                    possible_adapters.append(adapter)

        for adapter in possible_adapters:
            if ((not adapter.is_managed_by_nm and self.internet_access_enable)
                    or (not self.internet_access_enable)):
                chosen_interface = adapter.name
                self._active.add(chosen_interface)
                return chosen_interface

        if possible_adapters:
            raise InterfaceManagedByNetworkManagerError("ALL")
        else:
            raise InterfaceCantBeFoundError((has_monitor_mode, has_ap_mode))

    def get_interface_automatically(self):
        monitor_interface = self.get_interface(has_monitor_mode=True)
        ap_interface = self.get_interface(has_ap_mode=True)
        return (monitor_interface, ap_interface)

    def unblock_interface(self, interface_name):
        if self._nethunter_mode:
            try:
                subprocess.call(['rfkill', 'unblock', 'wifi'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError:
                pass
            return

        card = self._name_to_object[interface_name].card
        if pyw.isblocked(card):
            pyw.unblock(card)

    def set_interface_channel(self, interface_name, channel):
        if self._nethunter_mode:
            return
        card = self._name_to_object[interface_name].card
        pyw.chset(card, channel)

    def add_virtual_interface(self, card):
        if self._nethunter_mode:
            return 'wlan1'

        done_flag = True
        number = 0
        while done_flag:
            try:
                number += 1
                name = 'wlan' + str(number)
                pyw.down(card)
                monitor_card = pyw.devadd(card, name, 'monitor')
                done_flag = False
            except pyric.error:
                pass
        self._vifs_add.add(monitor_card)
        return name

    def remove_vifs_added(self):
        if self._nethunter_mode:
            return
        for card in self._vifs_add:
            pyw.devdel(card)

    def start(self):
        """Start the network manager — discover interfaces."""
        if HAS_PYRIC:
            for interface in pyw.interfaces():
                try:
                    card = pyw.getcard(interface)
                    mac_address = pyw.macget(card)
                    adapter = NetworkAdapter(interface, card, mac_address)
                    self._name_to_object[interface] = adapter
                    interface_property_detector(adapter)
                except pyric.error as error:
                    if error.args[0] == 93 or error.args[0] == 19:
                        pass
                    else:
                        raise error
        else:
            # Android fallback: use /sys and ip commands
            for iface in _android_get_interfaces():
                mac = _android_get_mac(iface)
                adapter = NetworkAdapter(iface, None, mac)
                # Assume AP and monitor support (can't check without pyric)
                adapter.has_ap_mode = True
                adapter.has_monitor_mode = True
                self._name_to_object[iface] = adapter

    def on_exit(self):
        if self._nethunter_mode:
            return

        for interface in self._active:
            if interface not in self._exclude_shutdown:
                adapter = self._name_to_object[interface]
                mac_address = adapter.original_mac_address
                self.set_interface_mac(interface, mac_address)
        self.remove_vifs_added()


def is_add_vif_required(args):
    if not HAS_PYRIC:
        return None, False

    phy_to_vifs = defaultdict(list)
    invalid_phy_number = list()

    if args.internetinterface and pyw.iswireless(args.internetinterface):
        card = pyw.getcard(args.internetinterface)
        invalid_phy_number.append(card.phy)

    if args.wpspbc_assoc_interface:
        card = pyw.getcard(args.wpspbc_assoc_interface)
        invalid_phy_number.append(card.phy)

    for vif in [vif for vif in pyw.interfaces() if pyw.iswireless(vif)]:
        score = 0
        card = pyw.getcard(vif)
        phy_number = card.phy
        if phy_number in invalid_phy_number:
            continue

        supported_modes = pyw.devmodes(card)
        if "monitor" in supported_modes:
            score += 1
        if "AP" in supported_modes:
            score += 1

        phy_to_vifs[phy_number].append((card, score))

    vif_score_tuples = [sublist[0] for sublist in phy_to_vifs.values()]
    vif_score_tuples = sorted(vif_score_tuples, key=lambda tup: -tup[1])

    def get_perfect_card(phy_map_vifs, vif_score_tups):
        if len(phy_map_vifs) == 1 and len(list(phy_map_vifs.values())[0]) == 1:
            vif_score_tuple = vif_score_tups[0]
            card = vif_score_tuple[0]
            score = vif_score_tuple[1]
            if score == 2:
                return card, True
        elif len(phy_map_vifs) == 1 and len(list(phy_map_vifs.values())[0]) > 1:
            return None, True
        elif len(phy_map_vifs) > 1:
            if vif_score_tups[0][1] == 2 and vif_score_tups[1][1] == 0:
                return vif_score_tups[0][0], True
        return None, False

    perfect_card, is_single_perfect_phy = get_perfect_card(
        phy_to_vifs, vif_score_tuples)
    return perfect_card, is_single_perfect_phy


def get_network_manager_objects(system_bus):
    if not HAS_DBUS:
        return None, None
    network_manager_proxy = system_bus.get_object(
        constants.NM_APP_PATH, constants.NM_MANAGER_OBJ_PATH)
    network_manager = dbus.Interface(
        network_manager_proxy,
        dbus_interface=constants.NM_MANAGER_INTERFACE_PATH)
    prop_accesser = dbus.Interface(
        network_manager_proxy, dbus_interface=dbus.PROPERTIES_IFACE)
    return network_manager, prop_accesser


def is_managed_by_network_manager(interface_name):
    if not HAS_DBUS:
        return False

    bus = dbus.SystemBus()
    is_managed = False
    try:
        network_manager = get_network_manager_objects(bus)[0]
        devices = network_manager.GetDevices()
        for dev_obj_path in devices:
            device_proxy = bus.get_object(constants.NM_APP_PATH, dev_obj_path)
            device = dbus.Interface(
                device_proxy, dbus_interface=dbus.PROPERTIES_IFACE)
            if device.Get(constants.NM_DEV_INTERFACE_PATH,
                          'Interface') == interface_name:
                is_managed = device.Get(constants.NM_DEV_INTERFACE_PATH,
                                        'Managed')
                break
    except dbus.exceptions.DBusException:
        pass
    return bool(is_managed)


def interface_property_detector(network_adapter):
    if not HAS_PYRIC:
        network_adapter.has_ap_mode = True
        network_adapter.has_monitor_mode = True
        return

    supported_modes = pyw.devmodes(network_adapter.card)
    if "monitor" in supported_modes:
        network_adapter.has_monitor_mode = True
    if "AP" in supported_modes:
        network_adapter.has_ap_mode = True

    interface_name = network_adapter.name
    network_adapter.is_managed_by_nm = is_managed_by_network_manager(
        interface_name)


def is_wireless_interface(interface_name):
    if HAS_PYRIC:
        return pyw.iswireless(interface_name)
    # Fallback: check /sys
    return os.path.isdir('/sys/class/net/%s/wireless' % interface_name)


def generate_random_address():
    mac_address = constants.DEFAULT_OUI + ":{:02x}:{:02x}:{:02x}".format(
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
    return mac_address


def does_have_mode(interface, mode):
    if not HAS_PYRIC:
        return True  # Assume yes on Android
    card = pyric.pyw.getcard(interface)
    return mode in pyric.pyw.devmodes(card)
