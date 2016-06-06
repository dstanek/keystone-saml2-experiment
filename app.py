#!/usr/bin/env python

from __future__ import print_function
import argparse
import importlib
import logging
import re
import sys

from saml2.client import Saml2Client
from saml2.httputil import ServiceError
from saml2.response import StatusError
from saml2.s_utils import rndstr
from saml2 import time_util
import saml2.xmldsig as ds
from six.moves.http_cookies import SimpleCookie

import sp


logger = logging.getLogger(__name__)


def _expiration(timeout, tformat=None):
    # Wed, 06-Jun-2012 01:34:34 GMT
    if not tformat:
        tformat = '%a, %d-%b-%Y %T GMT'

    if timeout == "now":
        return time_util.instant(tformat)
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, format=tformat)


class Cache(object):
    def __init__(self):
        self.uid2user = {}
        self.cookie_name = "spauthn"
        self.outstanding_queries = {}
        self.outstanding_certs = {}
        self.relay_state = {}
        self.user = {}
        self.result = {}

    def get_user(self, environ):
        cookie = environ.get("HTTP_COOKIE", '')
        logger.debug("Cookie: %s", cookie)
        if cookie:
            cookie_obj = SimpleCookie(cookie)
            morsel = cookie_obj.get(self.cookie_name, None)
            if morsel:
                try:
                    return self.uid2user[morsel.value]
                except KeyError:
                    return None
            else:
                logger.debug("No %s cookie", self.cookie_name)

        return None

    def delete_cookie(self, environ):
        cookie = environ.get("HTTP_COOKIE", '')
        logger.debug("delete cookie: %s", cookie)
        if cookie:
            _name = self.cookie_name
            cookie_obj = SimpleCookie(cookie)
            morsel = cookie_obj.get(_name, None)
            cookie = SimpleCookie()
            cookie[_name] = ""
            cookie[_name]['path'] = "/"
            logger.debug("Expire: %s", morsel)
            cookie[_name]["expires"] = _expiration("now")
            return cookie.output().split(": ", 1)
        return None

    def set_cookie(self, user):
        uid = rndstr(32)
        self.uid2user[uid] = user
        cookie = SimpleCookie()
        cookie[self.cookie_name] = uid
        cookie[self.cookie_name]['path'] = "/"
        cookie[self.cookie_name]["expires"] = _expiration(480)
        logger.debug("Cookie expires: %s", cookie[self.cookie_name]["expires"])
        return cookie.output().split(": ", 1)


def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above.

    If nothing matches, call the `not_found` function.

    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the
        request is done
    :return: The response as a list of lines
    """
    path = environ.get('PATH_INFO', '').lstrip('/')
    logger.debug("<application> PATH: '%s'", path)

    if path == "metadata":
        return metadata(environ, start_response)

    logger.debug("Finding callback to run")
    try:
        for regex, spec in urls:
            match = re.search(regex, path)
            if match is not None:
                if isinstance(spec, tuple):
                    callback, func_name, _sp = spec
                    cls = callback(_sp, environ, start_response, CACHE)
                    func = getattr(cls, func_name)
                    return func()
                else:
                    return spec(environ, start_response, SP)
        return not_found(environ, start_response)
    except StatusError as err:
        logging.error("StatusError: %s" % err)
        resp = BadRequest("%s" % err)
        return resp(environ, start_response)
    except Exception as err:
        # _err = exception_trace("RUN", err)
        # logging.error(exception_trace("RUN", _err))
        print(err, file=sys.stderr)
        resp = ServiceError("%s" % err)
        return resp(environ, start_response)


# map urls to functions
urls = [
    # Hmm, place holder, NOT used
    ('place', ("holder", None)),
    (r'^$', sp.main),
    (r'^disco', sp.disco),
    (r'^logout$', sp.logout),
]


def add_urls():
    base = "acs"

    urls.append(("%s/post$" % base, (sp.ACS, "post", SP)))
    urls.append(("%s/post/(.*)$" % base, (sp.ACS, "post", SP)))
    urls.append(("%s/redirect$" % base, (sp.ACS, "redirect", SP)))
    urls.append(("%s/redirect/(.*)$" % base, (sp.ACS, "redirect", SP)))

    base = "slo"

    urls.append(("%s/post$" % base, (sp.SLO, "post", SP)))
    urls.append(("%s/post/(.*)$" % base, (sp.SLO, "post", SP)))
    urls.append(("%s/redirect$" % base, (sp.SLO, "redirect", SP)))
    urls.append(("%s/redirect/(.*)$" % base, (sp.SLO, "redirect", SP)))


if __name__ == '__main__':
    from cherrypy import wsgiserver

    _parser = argparse.ArgumentParser()
    _parser.add_argument('-d', dest='debug', action='store_true',
                         help="Print debug information")
    _parser.add_argument('-D', dest='discosrv',
                         help="Which disco server to use")
    _parser.add_argument('-s', dest='seed',
                         help="Cookie seed")
    _parser.add_argument('-W', dest='wayf', action='store_true',
                         help="Which WAYF url to use")
    _parser.add_argument("config", help="SAML client config")
    _parser.add_argument('-p', dest='path', help='Path to configuration file.')
    _parser.add_argument('-v', dest='valid', default="4",
                         help="How long, in days, the metadata is valid from "
                              "the time of creation")
    _parser.add_argument('-c', dest='cert', help='certificate')
    _parser.add_argument('-i', dest='id',
                         help="The ID of the entities descriptor in the "
                              "metadata")
    _parser.add_argument('-k', dest='keyfile',
                         help="A file with a key to sign the metadata with")
    _parser.add_argument('-n', dest='name')
    _parser.add_argument('-S', dest='sign', action='store_true',
                         help="sign the metadata")
    _parser.add_argument('-C', dest='service_conf_module',
                         help="service config module")

    ARGS = {}
    _args = _parser.parse_args()
    if _args.discosrv:
        ARGS["discosrv"] = _args.discosrv
    if _args.wayf:
        ARGS["wayf"] = _args.wayf
    sp.ARGS = ARGS

    CACHE = sp.CACHE = Cache()
    CNFBASE = _args.config
    if _args.seed:
        SEED = _args.seed
    else:
        SEED = "SnabbtInspel"

    if _args.service_conf_module:
        service_conf = importlib.import_module(_args.service_conf_module)
    else:
        import service_conf

    HOST = service_conf.HOST
    PORT = service_conf.PORT
    # ------- HTTPS -------
    # These should point to relevant files
    SERVER_CERT = service_conf.SERVER_CERT
    SERVER_KEY = service_conf.SERVER_KEY
    # This is of course the certificate chain for the CA that signed
    # your cert and all the way up to the top
    CERT_CHAIN = service_conf.CERT_CHAIN

    SP = Saml2Client(config_file="%s" % CNFBASE)

    POLICY = service_conf.POLICY

    add_urls()
    sign_alg = None
    digest_alg = None
    try:
        sign_alg = service_conf.SIGN_ALG
    except:
        pass
    try:
        digest_alg = service_conf.DIGEST_ALG
    except:
        pass
    ds.DefaultSignature(sign_alg, digest_alg)

    SRV = wsgiserver.CherryPyWSGIServer((HOST, PORT), application)

    logger.info("Server starting")
    print("SP listening on %s:%s" % (HOST, PORT))
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
