import hashlib
import hmac
import base64
from datetime import datetime
from urlparse import urlparse

from requests.auth import AuthBase


_STRING_TO_SIGN = "{method}\n{host}\n{uri}\n{timestamp}\n"
_AUTH_HEADER = "APIKey={api_key},Signature={sig},Timestamp={timestamp}"

class HMACAuth(AuthBase):
    """ Signs the request for use with the super-cool go-hmacauth library

        Basic Usage:
            auth = HMACAuth("<my-api-key>", "<my-secret-key">)
            result = requests.get("/api/endpoint", auth=auth)
    """

    def __init__(self, api_key, secret_key, required_headers=None):
        self.api_key = api_key
        self.secret_key = secret_key
        if required_headers is not None:
            self.required_headers = sorted(required_headers)
        else:
            self.required_headers = None

    def __call__(self, r):
        parsed_url = urlparse(r.url)
        timestamp = datetime.utcnow().isoformat() + "-00:00"

        str_to_sign = _STRING_TO_SIGN.format(
            method=r.method,
            host=parsed_url.netloc,
            uri=r.path_url,
            timestamp=timestamp
        )

        if self.required_headers:
            str_to_sign = (
                str_to_sign +
                "\n".join(
                    [r.headers[h] for h in self.required_headers if h in r.headers]))

        raw_sig = hmac.new(self.secret_key, str_to_sign, hashlib.sha256).digest()
        encoded_sig = base64.b64encode(raw_sig)

        r.headers['Authorization'] = _AUTH_HEADER.format(
            api_key = self.api_key,
            sig=encoded_sig,
            timestamp=timestamp
        )

        return r
