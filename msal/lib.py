from msal.exceptions import MsalServiceError


class RequestInfo(object):
    def __init__(self, url, method, params):
        self.url = url
        self.method = method
        self.params = params


def get_instance_discovery_request_info(instance, authority_path):
    return RequestInfo(url="https://login.microsoftonline.com/common/discovery/instance",
                       params={"authorization_endpoint": "https://{}{}/oauth2/v2.0/authorize".format(instance,
                                                                                                     authority_path),
                               "api-version": "1.0"},
                       method="get")


def verify_instance_discovery_response(discovery_response_json):
    if discovery_response_json.get("error") == "invalid_instance":
        raise ValueError(
            "invalid_instance: "
            "The authority you provided is not whitelisted. "
            "If it is indeed your legit customized domain name, "
            "you can turn off this check by passing in "
            "validate_authority=False")


def get_tenant_discovery_request_info(tenant_discovery_endpoint):
    return RequestInfo(url=tenant_discovery_endpoint, params=None, method="get")


def verify_tenant_discovery_response(tenant_discovery_json):
    if 'authorization_endpoint' not in tenant_discovery_json or 'token_endpoint' not in tenant_discovery_json:
        raise MsalServiceError(status_code=400, **tenant_discovery_json)
