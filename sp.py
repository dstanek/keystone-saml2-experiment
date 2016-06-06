#!/usr/bin/env python

import cgi
import logging
import os
import xml.dom.minidom
from saml2.sigver import SignatureError

import six
from six.moves.urllib.parse import parse_qs

import saml2.xmldsig as ds
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT, element_to_extension_element
from saml2 import BINDING_SOAP
from saml2 import ecp
from saml2.ecp_client import PAOS_HEADER_INFO
from saml2.extension.pefim import SPCertEnc
from saml2.httputil import BadRequest
from saml2.httputil import NotFound
from saml2.httputil import NotImplemented
from saml2.httputil import Redirect
from saml2.httputil import Response
from saml2.httputil import SeeOther
from saml2.httputil import ServiceError
from saml2.httputil import Unauthorized
from saml2.httputil import get_post
from saml2.httputil import geturl, make_cookie, parse_cookie
from saml2.metadata import create_metadata_string
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import decode_base64_and_inflate
from saml2.s_utils import rndstr
from saml2.s_utils import sid
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.samlp import Extensions


logger = logging.getLogger(__name__)
hdlr = logging.FileHandler('spx.log')
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

SP = None
SEED = ""
POLICY = None


def dict_to_table(ava, lev=0, width=1):
    txt = ['<table border=%s bordercolor="black">\n' % width]
    for prop, valarr in ava.items():
        txt.append("<tr>\n")

        if isinstance(prop, six.text_type):
            prop = prop.encode('utf-8')
        if isinstance(valarr, six.text_type):
            valarr = valarr.encode('utf-8')

        if isinstance(valarr, six.binary_type):
            txt.append("<th>%s</th>\n" % prop)
            txt.append("<td>%s</td>\n" % valarr)
        elif isinstance(valarr, list):
            i = 0
            n = len(valarr)
            for val in valarr:
                if isinstance(val, six.text_type):
                    val = val.encode('utf-8')
                if not i:
                    txt.append("<th rowspan=%d>%s</td>\n" % (len(valarr), prop))
                else:
                    txt.append("<tr>\n")
                if isinstance(val, dict):
                    txt.append("<td>\n")
                    txt.extend(dict_to_table(val, lev + 1, width - 1))
                    txt.append("</td>\n")
                else:
                    txt.append("<td>%s</td>\n" % val)
                if n > 1:
                    txt.append("</tr>\n")
                n -= 1
                i += 1
        elif isinstance(valarr, dict):
            txt.append("<th>%s</th>\n" % prop)
            txt.append("<td>\n")
            txt.extend(dict_to_table(valarr, lev + 1, width - 1))
            txt.append("</td>\n")
        txt.append("</tr>\n")
    txt.append('</table>\n')
    return txt


class ECPResponse(object):
    code = 200
    title = 'OK'

    def __init__(self, content):
        self.content = content

    # noinspection PyUnusedLocal
    def __call__(self, environ, start_response):
        start_response('%s %s' % (self.code, self.title),
                       [('Content-Type', "text/xml")])
        return [self.content]


# -----------------------------------------------------------------------------
# RECEIVERS
# -----------------------------------------------------------------------------


class Service(object):
    def __init__(self, environ, start_response, user=None):
        self.environ = environ
        logger.debug("ENVIRON: %s", environ)
        self.start_response = start_response
        self.user = user
        self.sp = None

    def unpack_redirect(self):
        if "QUERY_STRING" in self.environ:
            _qs = self.environ["QUERY_STRING"]
            return dict([(k, v[0]) for k, v in parse_qs(_qs).items()])
        else:
            return None

    def unpack_post(self):
        _dict = parse_qs(get_post(self.environ).decode('utf8'))
        logger.debug("unpack_post:: %s", _dict)
        return dict([(k, v[0]) for k, v in _dict.items()])

    def unpack_soap(self):
        try:
            query = get_post(self.environ)
            return {"SAMLResponse": query, "RelayState": ""}
        except Exception:
            return None

    def unpack_either(self):
        if self.environ["REQUEST_METHOD"] == "GET":
            _dict = self.unpack_redirect()
        elif self.environ["REQUEST_METHOD"] == "POST":
            _dict = self.unpack_post()
        else:
            _dict = None
        logger.debug("_dict: %s", _dict)
        return _dict

    def operation(self, _dict, binding):
        logger.debug("_operation: %s", _dict)
        if not _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)
        else:
            try:
                _relay_state = _dict["RelayState"]
            except KeyError:
                _relay_state = ""
            if "SAMLResponse" in _dict:
                return self.do(_dict["SAMLResponse"], binding,
                               _relay_state, mtype="response")
            elif "SAMLRequest" in _dict:
                return self.do(_dict["SAMLRequest"], binding,
                               _relay_state, mtype="request")

    def artifact_operation(self, _dict):
        if not _dict:
            resp = BadRequest("Missing query")
            return resp(self.environ, self.start_response)
        else:
            # exchange artifact for response
            request = self.sp.artifact2message(_dict["SAMLart"], "spsso")
            return self.do(request, BINDING_HTTP_ARTIFACT, _dict["RelayState"])

    def response(self, binding, http_args):
        if binding == BINDING_HTTP_ARTIFACT:
            resp = Redirect()
        else:
            resp = Response(http_args["data"], headers=http_args["headers"])
        return resp(self.environ, self.start_response)

    def do(self, query, binding, relay_state="", mtype="response"):
        pass

    def redirect(self):
        """ Expects a HTTP-redirect response """

        _dict = self.unpack_redirect()
        return self.operation(_dict, BINDING_HTTP_REDIRECT)

    def post(self):
        """ Expects a HTTP-POST response """

        _dict = self.unpack_post()
        return self.operation(_dict, BINDING_HTTP_POST)

    def artifact(self):
        # Can be either by HTTP_Redirect or HTTP_POST
        _dict = self.unpack_either()
        return self.artifact_operation(_dict)

    def soap(self):
        """
        Single log out using HTTP_SOAP binding
        """
        logger.debug("- SOAP -")
        _dict = self.unpack_soap()
        logger.debug("_dict: %s", _dict)
        return self.operation(_dict, BINDING_SOAP)

    def uri(self):
        _dict = self.unpack_either()
        return self.operation(_dict, BINDING_SOAP)

    def not_authn(self):
        resp = Unauthorized('Unknown user')
        return resp(self.environ, self.start_response)


# -----------------------------------------------------------------------------
#  Attribute Consuming service
# -----------------------------------------------------------------------------


class User(object):
    def __init__(self, name_id, data, saml_response):
        self.name_id = name_id
        self.data = data
        self.response = saml_response

    @property
    def authn_statement(self):
        xml_doc = xml.dom.minidom.parseString(
            str(self.response.assertion.authn_statement[0]))
        return xml_doc.toprettyxml()


class ACS(Service):
    def __init__(self, sp, environ, start_response, cache):
        Service.__init__(self, environ, start_response)
        self.sp = sp
        self.outstanding_queries = cache.outstanding_queries
        self.cache = cache
        self.response = None

    def do(self, response, binding, relay_state="", mtype="response"):
        """
        :param response: The SAML response, transport encoded
        :param binding: Which binding the query came in over
        """
        # tmp_outstanding_queries = dict(self.outstanding_queries)
        if not response:
            logger.info("Missing Response")
            resp = Unauthorized('Unknown user')
            return resp(self.environ, self.start_response)

        try:
            self.response = self.sp.parse_authn_request_response(
                response, binding, self.outstanding_queries,
                self.cache.outstanding_certs)
        except UnknownPrincipal as excp:
            logger.error("UnknownPrincipal: %s", excp)
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding as excp:
            logger.error("UnsupportedBinding: %s", excp)
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except VerificationError as err:
            resp = ServiceError("Verification error: %s" % (err,))
            return resp(self.environ, self.start_response)
        except SignatureError as err:
            resp = ServiceError("Signature error: %s" % (err,))
            return resp(self.environ, self.start_response)
        except Exception as err:
            resp = ServiceError("Other error: %s" % (err,))
            return resp(self.environ, self.start_response)

        logger.info("AVA: %s", self.response.ava)

        user = User(self.response.name_id, self.response.ava, self.response)
        cookie = self.cache.set_cookie(user)

        resp = Redirect("/", headers=[
            cookie,
        ])
        return resp(self.environ, self.start_response)

    def verify_attributes(self, ava):
        logger.info("SP: %s", self.sp.config.entityid)
        rest = POLICY.get_entity_categories(
            self.sp.config.entityid, self.sp.metadata)

        akeys = [k.lower() for k in ava.keys()]

        res = {"less": [], "more": []}
        for key, attr in rest.items():
            if key not in ava:
                if key not in akeys:
                    res["less"].append(key)

        for key, attr in ava.items():
            _key = key.lower()
            if _key not in rest:
                res["more"].append(key)

        return res


# -----------------------------------------------------------------------------
# REQUESTERS
# -----------------------------------------------------------------------------


class SSO(object):
    def __init__(self, sp, environ, start_response, cache=None,
                 wayf=None, discosrv=None, bindings=None):
        self.sp = sp
        self.environ = environ
        self.start_response = start_response
        self.cache = cache
        self.idp_query_param = "IdpQuery"
        self.wayf = wayf
        self.discosrv = discosrv
        if bindings:
            self.bindings = bindings
        else:
            self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST,
                             BINDING_HTTP_ARTIFACT]
        logger.debug("--- SSO ---")

    def response(self, binding, http_args, do_not_start_response=False):
        if binding == BINDING_HTTP_ARTIFACT:
            resp = Redirect()
        elif binding == BINDING_HTTP_REDIRECT:
            for param, value in http_args["headers"]:
                if param == "Location":
                    resp = SeeOther(str(value))
                    break
            else:
                resp = ServiceError("Parameter error")
        else:
            resp = Response(http_args["data"], headers=http_args["headers"])

        if do_not_start_response:
            return resp
        else:
            return resp(self.environ, self.start_response)

    def _wayf_redirect(self, came_from):
        sid_ = sid()
        self.cache.outstanding_queries[sid_] = came_from
        logger.debug("Redirect to WAYF function: %s", self.wayf)
        return -1, SeeOther(headers=[('Location', "%s?%s" % (self.wayf, sid_))])

    def _pick_idp(self, came_from):
        """
        If more than one idp and if none is selected, I have to do wayf or
        disco
        """

        _cli = self.sp

        logger.debug("[_pick_idp] %s", self.environ)
        if "HTTP_PAOS" in self.environ:
            if self.environ["HTTP_PAOS"] == PAOS_HEADER_INFO:
                if 'application/vnd.paos+xml' in self.environ["HTTP_ACCEPT"]:
                    # Where should I redirect the user to
                    # entityid -> the IdP to use
                    # relay_state -> when back from authentication

                    logger.debug("- ECP client detected -")

                    _rstate = rndstr()
                    self.cache.relay_state[_rstate] = geturl(self.environ)
                    _entityid = _cli.config.ecp_endpoint(
                        self.environ["REMOTE_ADDR"])

                    if not _entityid:
                        return -1, ServiceError("No IdP to talk to")
                    logger.debug("IdP to talk to: %s", _entityid)
                    return ecp.ecp_auth_request(_cli, _entityid, _rstate)
                else:
                    return -1, ServiceError('Faulty Accept header')
            else:
                return -1, ServiceError('unknown ECP version')

        # Find all IdPs
        idps = self.sp.metadata.with_descriptor("idpsso")

        idp_entity_id = None

        kaka = self.environ.get("HTTP_COOKIE", '')
        if kaka:
            try:
                (idp_entity_id, _) = parse_cookie("ve_disco", "SEED_SAW", kaka)
            except ValueError:
                pass
            except TypeError:
                pass

        # Any specific IdP specified in a query part
        query = self.environ.get("QUERY_STRING")
        if not idp_entity_id and query:
            try:
                _idp_entity_id = dict(parse_qs(query))[
                    self.idp_query_param][0]
                if _idp_entity_id in idps:
                    idp_entity_id = _idp_entity_id
            except KeyError:
                logger.debug("No IdP entity ID in query: %s", query)
                pass

        if not idp_entity_id:

            if self.wayf:
                if query:
                    try:
                        wayf_selected = dict(parse_qs(query))[
                            "wayf_selected"][0]
                    except KeyError:
                        return self._wayf_redirect(came_from)
                    idp_entity_id = wayf_selected
                else:
                    return self._wayf_redirect(came_from)
            elif self.discosrv:
                if query:
                    idp_entity_id = _cli.parse_discovery_service_response(
                        query=self.environ.get("QUERY_STRING"))
                if not idp_entity_id:
                    sid_ = sid()
                    self.cache.outstanding_queries[sid_] = came_from
                    logger.debug("Redirect to Discovery Service function")
                    eid = _cli.config.entityid
                    ret = _cli.config.getattr("endpoints",
                                              "sp")["discovery_response"][0][0]
                    ret += "?sid=%s" % sid_
                    loc = _cli.create_discovery_service_request(
                        self.discosrv, eid, **{"return": ret})
                    return -1, SeeOther(loc)
            elif len(idps) == 1:
                # idps is a dictionary
                idp_entity_id = list(idps.keys())[0]
            elif not len(idps):
                return -1, ServiceError('Misconfiguration')
            else:
                return -1, NotImplemented("No WAYF or DS present!")

        logger.info("Chosen IdP: '%s'", idp_entity_id)
        return 0, idp_entity_id

    def redirect_to_auth(self, _cli, entity_id, came_from, sigalg=""):
        try:
            # Picks a binding to use for sending the Request to the IDP
            _binding, destination = _cli.pick_binding(
                "single_sign_on_service", self.bindings, "idpsso",
                entity_id=entity_id)
            logger.debug("binding: %s, destination: %s", _binding,
                         destination)
            # Binding here is the response binding that is which binding the
            # IDP should use to return the response.
            acs = _cli.config.getattr("endpoints", "sp")[
                "assertion_consumer_service"]
            # just pick one
            endp, return_binding = acs[0]

            extensions = None
            cert = None
            if _cli.config.generate_cert_func is not None:
                cert_str, req_key_str = _cli.config.generate_cert_func()
                cert = {
                    "cert": cert_str,
                    "key": req_key_str
                }
                spcertenc = SPCertEnc(x509_data=ds.X509Data(
                    x509_certificate=ds.X509Certificate(text=cert_str)))
                extensions = Extensions(extension_elements=[
                    element_to_extension_element(spcertenc)])

            req_id, req = _cli.create_authn_request(destination,
                                                    binding=return_binding,
                                                    extensions=extensions,
                                                    nameid_format=NAMEID_FORMAT_TRANSIENT)
            _rstate = rndstr()
            self.cache.relay_state[_rstate] = came_from
            ht_args = _cli.apply_binding(_binding, "%s" % req, destination,
                                         relay_state=_rstate,
                                         sigalg=sigalg)
            _sid = req_id

            if cert is not None:
                self.cache.outstanding_certs[_sid] = cert

        except Exception as exc:
            logger.exception(exc)
            resp = ServiceError(
                "Failed to construct the AuthnRequest: %s" % exc)
            return resp

        # remember the request
        self.cache.outstanding_queries[_sid] = came_from
        return self.response(_binding, ht_args, do_not_start_response=True)

    def do(self):
        _cli = self.sp

        # Which page was accessed to get here
        came_from = geturl(self.environ)
        logger.debug("[sp.challenge] RelayState >> '%s'", came_from)

        # If more than one idp and if none is selected, I have to do wayf
        (done, response) = self._pick_idp(came_from)
        # Three cases: -1 something went wrong or Discovery service used
        #               0 I've got an IdP to send a request to
        #               >0 ECP in progress
        logger.debug("_idp_pick returned: %s", done)
        if done == -1:
            return response(self.environ, self.start_response)
        elif done > 0:
            self.cache.outstanding_queries[done] = came_from
            return ECPResponse(response)
        else:
            entity_id = response
            # Do the AuthnRequest
            resp = self.redirect_to_auth(_cli, entity_id, came_from)
            return resp(self.environ, self.start_response)


# ----------------------------------------------------------------------------


class SLO(Service):
    def __init__(self, sp, environ, start_response, cache):
        Service.__init__(self, environ, start_response)
        self.sp = sp
        self.cache = cache

    def do(self, message, binding, relay_state="", mtype="response"):
        try:
            txt = decode_base64_and_inflate(message)
            is_logout_request = 'LogoutRequest' in txt.split('>', 1)[0]
        except:  # TODO: parse the XML correctly
            is_logout_request = False

        if is_logout_request:
            self.sp.parse_logout_request(message, binding)
        else:
            self.sp.parse_logout_request_response(message, binding)

        return finish_logout(self.environ, self.start_response, self.cache)


# ----------------------------------------------------------------------------


# noinspection PyUnusedLocal
def not_found(environ, start_response):
    """Called if no URL matches."""
    resp = NotFound('Not Found')
    return resp(environ, start_response)


# ----------------------------------------------------------------------------


# noinspection PyUnusedLocal
def main(environ, start_response, sp, cache):
    user = cache.get_user(environ)

    if user is None:
        sso = SSO(sp, environ, start_response, cache=cache, **ARGS)
        return sso.do()

    body = dict_to_table(user.data)
    authn_stmt = cgi.escape(user.authn_statement.encode('utf-8'))
    body.append('<br><pre>' + authn_stmt + "</pre>")
    body.append('<br><a href="/logout">logout</a>')

    resp = Response(body)
    return resp(environ, start_response)


def disco(environ, start_response, _sp, cache):
    query = parse_qs(environ["QUERY_STRING"])
    entity_id = query["entityID"][0]
    _sid = query["sid"][0]
    came_from = cache.outstanding_queries[_sid]
    _sso = SSO(_sp, environ, start_response, cache=cache, **ARGS)
    resp = _sso.redirect_to_auth(_sso.sp, entity_id, came_from)

    # Add cookie
    kaka = make_cookie("ve_disco", entity_id, "SEED_SAW")
    resp.headers.append(kaka)
    return resp(environ, start_response)


# ----------------------------------------------------------------------------


# noinspection PyUnusedLocal
def logout(environ, start_response, sp, cache):
    user = cache.get_user(environ)

    if user is None:
        sso = SSO(sp, environ, start_response, cache=cache, **ARGS)
        return sso.do()

    logger.info("[logout] subject_id: '%s'", user.name_id)

    # What if more than one
    data = sp.global_logout(user.name_id)
    logger.info("[logout] global_logout > %s", data)

    for entity_id, logout_info in data.items():
        if isinstance(logout_info, tuple):
            binding, http_info = logout_info

            if binding == BINDING_HTTP_POST:
                body = ''.join(http_info['data'])
                resp = Response(body)
                return resp(environ, start_response)
            elif binding == BINDING_HTTP_REDIRECT:
                for key, value in http_info['headers']:
                    if key.lower() == 'location':
                        resp = Redirect(value)
                        return resp(environ, start_response)

                resp = ServiceError('missing Location header')
                return resp(environ, start_response)
            else:
                resp = ServiceError('unknown logout binding: %s', binding)
                return resp(environ, start_response)
        else:  # result from logout, should be OK
            pass

    return finish_logout(environ, start_response, cache)


def finish_logout(environ, start_response, cache):
    logger.info("[logout done] environ: %s", environ)
    logger.info("[logout done] remaining subjects: %s", cache.uid2user.values())

    # remove cookie and stored info
    cookie = cache.delete_cookie(environ)

    resp = Response('You are now logged out of this service', headers=[
        cookie,
    ])
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

def metadata(environ, start_response):
    try:
        path = _args.path
        if path is None or len(path) == 0:
            path = os.path.dirname(os.path.abspath(__file__))
        if path[-1] != "/":
            path += "/"
        metadata = create_metadata_string(path + "sp_conf.py", None,
                                          _args.valid, _args.cert,
                                          _args.keyfile,
                                          _args.id, _args.name, _args.sign)
        start_response('200 OK', [('Content-Type', "text/xml")])
        return metadata
    except Exception as ex:
        logger.error("An error occured while creating metadata: %s", ex.message)
        return not_found(environ, start_response)
