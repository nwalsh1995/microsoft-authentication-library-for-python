import abc

from msal.exceptions import MsalError
from msal.lib import RequestInfo

import requests


class HTTPTransport(object):
    @abc.abstractmethod
    def send_request(self, request: RequestInfo):
        ...


class RequestsTransport(HTTPTransport):
    def send_request(self, request: RequestInfo, raise_for_status=False):
        params = request.params
        url = request.url
        method = request.method
        transport_method = None

        if method == "get":
            transport_method = requests.get
        elif method == "post":
            transport_method = requests.post

        response = transport_method(url=url, params=params)
        if raise_for_status:
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                raise MsalError(status_code=response.status_code)
        return response.json()
