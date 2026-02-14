#pylint: skip-file
import subprocess
import wifiphisher.common.constants as constants


class Fw():
    def __init__(self):
        pass

    def nat(self, internal_interface, external_interface):
        subprocess.call(
            ('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' %
             (external_interface, )),
            shell=True)

        subprocess.call(
            ('iptables -A FORWARD -i %s -o %s -j ACCEPT' %
             (internal_interface, external_interface)),
            shell=True)

    def clear_rules(self):
        subprocess.call('iptables -F', shell=True)
        subprocess.call('iptables -X', shell=True)
        subprocess.call('iptables -t nat -F', shell=True)
        subprocess.call('iptables -t nat -X', shell=True)

    def redirect_requests_localhost(self):
        """
        Redirect HTTP/HTTPS/DNS to our phishing server.
        CRITICAL: reads constants.NETWORK_GW_IP via module reference
        so it picks up the dynamic value set by accesspoint.py in
        NetHunter mode (from X import * would copy the old value).
        """
        gw = constants.NETWORK_GW_IP
        port = constants.PORT
        ssl_port = constants.SSL_PORT

        subprocess.call(
            ('iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination %s:%s'
             % (gw, port)),
            shell=True)
        subprocess.call(
            ('iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination %s:%s'
             % (gw, 53)),
            shell=True)
        subprocess.call(
            ('iptables -t nat -A PREROUTING -p tcp --dport 53 -j DNAT --to-destination %s:%s'
             % (gw, 53)),
            shell=True)
        subprocess.call(
            ('iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination %s:%s'
             % (gw, ssl_port)),
            shell=True)

    def on_exit(self):
        self.clear_rules()
