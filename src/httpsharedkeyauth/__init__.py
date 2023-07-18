"""
httpsharedkeyauth

Python implementation of the client library for https://github.com/blowdart/idunno.Authentication/tree/dev/src/idunno.Authentication.SharedKey
This is intended to be used as an auth handler for a request object by attaching the proper authorization header. 
"""

import base64
import datetime
import hashlib
import hmac
from urllib.parse import urlparse,parse_qs
from requests.auth import AuthBase
from .version import __version__


class HTTPSharedKeyAuth(AuthBase):

    def __init__(self, identifier, key):
        self.identifier = identifier
        self.key = key

    def __call__(self, r):
        self._prepare_headers(r)
        r.headers['Authorization'] = 'SharedKey {}:{}'.format(self.identifier, self._signature(r))
        return r

    def _canonicalizeResource(self,r):

        parsed_url = urlparse(r.url)
        canonicalizedResource = parsed_url.path

        # Handle query string
        qs = {}
        for k,v in parse_qs(parsed_url.query, True).items():
            if v == ['']:
                qs.setdefault('',[]).append(k)
            else:
                qs[k] = v
        for key in sorted(qs):
            # The spec states that "If a parameter has multiple values the values should be sorted lexicographically and append as a comma separated list"
            # However it only works if we don't sort the values
            canonicalizedResource += '\n{}:{}'.format(key,','.join(map(str,qs[key])))

        return canonicalizedResource

    def _prepare_headers(self,r):
        if r.body is not None: 
            r.headers['Content-MD5'] = base64.b64encode(hashlib.md5(r.body.encode('utf-8')).digest()).decode()
        else:
            r.headers['Content-Length'] = '0'

        if not r.headers.get('Date',False):
            r.headers['date'] = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

    def _signature(self,r):
        canonicalizedHeaders = (r.method.upper() + '\n'
            + r.headers.get('Content-Encoding','') + '\n'
            + r.headers.get('Content-Language','') + '\n'
            + r.headers.get('Content-Length') + '\n'
            + r.headers.get('Content-MD5','') + '\n' 
            + r.headers.get('Content-Type','') + '\n' 
            + r.headers.get('Date') + '\n' 
            + r.headers.get('If-Modified-Since','') + '\n'
            + r.headers.get('If-Match','') + '\n'
            + r.headers.get('If-None-Match','') + '\n'
            + r.headers.get('If-Unmodified-Since','') + '\n'
            + r.headers.get('Range','') + '\n'
            + self._canonicalizeResource(r))

        return base64.b64encode(hmac.new(base64.b64decode(self.key), msg=canonicalizedHeaders.encode('utf-8'), digestmod=hashlib.sha256).digest()).decode()

