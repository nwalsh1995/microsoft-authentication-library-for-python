try:
    from urllib.parse import urlparse
except ImportError:  # Fall back to Python 2
    from urlparse import urlparse
import logging

from msal.transport import RequestsTransport
from msal.lib import get_instance_discovery_request_info, verify_instance_discovery_response, get_tenant_discovery_request_info, verify_tenant_discovery_response, get_user_realm_discovery_request_info


logger = logging.getLogger(__name__)
WORLD_WIDE = 'login.microsoftonline.com'  # There was an alias login.windows.net
WELL_KNOWN_AUTHORITY_HOSTS = set([
    WORLD_WIDE,
    'login.chinacloudapi.cn',
    'login-us.microsoftonline.com',
    'login.microsoftonline.us',
    'login.microsoftonline.de',
])
WELL_KNOWN_B2C_HOSTS = [
    "b2clogin.com",
    "b2clogin.cn",
    "b2clogin.us",
    "b2clogin.de",
]


class BaseAuthority(object):
    def __init__(self, authority_url, validate_authority=True,
                 verify=True, proxies=None, timeout=None,transport=None):
        self.verify = verify
        self.proxies = proxies
        self.timeout = timeout
        self.transport = transport if transport is not None else RequestsTransport()

    def requires_instance_discovery(self, authority, tenant, validate_authority=True):
        parts = authority.path.split('/')
        is_b2c = any(self.instance.endswith("." + d) for d in WELL_KNOWN_B2C_HOSTS) or (
                len(parts) == 3 and parts[2].lower().startswith("b2c_"))
        return (tenant != "adfs" and (not is_b2c) and validate_authority
                and self.instance not in WELL_KNOWN_AUTHORITY_HOSTS)


class Authority(BaseAuthority):
    """This class represents an (already-validated) authority.

    Once constructed, it contains members named "*_endpoint" for this instance.
    TODO: It will also cache the previously-validated authority instances.
    """
    _domains_without_user_realm_discovery = set([])

    def __init__(self, authority_url, validate_authority=True,
                 verify=True, proxies=None, timeout=None,transport=None):
        """Creates an authority instance, and also validates it.

        :param validate_authority:
            The Authority validation process actually checks two parts:
            instance (a.k.a. host) and tenant. We always do a tenant discovery.
            This parameter only controls whether an instance discovery will be
            performed.
        """
        super(Authority, self).__init__(authority_url, validate_authority, verify, proxies, timeout, transport)
        authority, self.instance, tenant = canonicalize(authority_url)
        if self.requires_instance_discovery(authority, tenant, validate_authority):
            # TODO: simplify in function
            instance_discovery_request_info = get_instance_discovery_request_info(self.instance, authority.path)
            # TODO: verify/proxies support
            payload = self.transport.send_request(instance_discovery_request_info)
            verify_instance_discovery_response(payload)
            tenant_discovery_endpoint = payload['tenant_discovery_endpoint']
        else:
            tenant_discovery_endpoint = get_default_discovery_endpoint(self.instance, authority.path, tenant)

        # TODO: simplify in function
        openid_config = self.transport.send_request(get_tenant_discovery_request_info(tenant_discovery_endpoint))
        verify_tenant_discovery_response(openid_config)
        logger.debug("openid_config = %s", openid_config)
        self.authorization_endpoint = openid_config['authorization_endpoint']
        self.token_endpoint = openid_config['token_endpoint']
        _, _, self.tenant = canonicalize(self.token_endpoint)  # Usually a GUID
        self.is_adfs = self.tenant.lower() == 'adfs'

    def user_realm_discovery(self, username, correlation_id=None, response=None):
        # It will typically return a dict containing "ver", "account_type",
        # "federation_protocol", "cloud_audience_urn",
        # "federation_metadata_url", "federation_active_auth_url", etc.
        if self.instance not in self.__class__._domains_without_user_realm_discovery:
            # TODO: verify/proxies
            # TODO: where to handle errors in transport layer, seems like we should return a response
            resp = response or self.transport.send_request(get_user_realm_discovery_request_info(self.instance, username, correlation_id=correlation_id))
            if resp.status_code != 404:
                resp.raise_for_status()
                return resp.json()
            self.__class__._domains_without_user_realm_discovery.add(self.instance)
        return {}  # This can guide the caller to fall back normal ROPC flow


def canonicalize(authority_url):
    # Returns (url_parsed_result, hostname_in_lowercase, tenant)
    authority = urlparse(authority_url)
    parts = authority.path.split("/")
    if authority.scheme != "https" or len(parts) < 2 or not parts[1]:
        raise ValueError(
            "Your given address (%s) should consist of "
            "an https url with a minimum of one segment in a path: e.g. "
            "https://login.microsoftonline.com/<tenant> "
            "or https://<tenant_name>.b2clogin.com/<tenant_name>.onmicrosoft.com/policy"
            % authority_url)
    return authority, authority.hostname, parts[1]


def get_default_discovery_endpoint(instance, authority_path, tenant):
    return (
        'https://{}{}{}/.well-known/openid-configuration'.format(
            instance,
            authority_path,  # In B2C scenario, it is "/tenant/policy"
            "" if tenant == "adfs" else "/v2.0" # the AAD v2 endpoint
        ))

