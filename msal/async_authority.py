from msal.authority import Authority, canonicalize, requires_discovery, WORLD_WIDE, MsalServiceError, build_default_tenant_discovery_endpoint, get_discovery_endpoint_from_payload
import httpx

import logging


logger = logging.getLogger(__name__)


class AsyncAuthority(Authority):
    @classmethod
    async def initialize(cls, authority_url, validate_authority=True,
                         verify=True, proxies=None, timeout=None):
        authority, instance, tenant = canonicalize(authority_url)

        if requires_discovery(authority, instance, tenant, validate_authority):
            tenant_discovery_endpoint = await retrieve_tenant_discovery_endpoint(url="https://{}{}/oauth2/v2.0/authorize".format(instance, authority.path),
                                                                                 authority_url=authority_url,
                                                                                 verify=verify, proxies=proxies, timeout=timeout)
        else:
            tenant_discovery_endpoint = build_default_tenant_discovery_endpoint(instance, authority.path, tenant)

        openid_config = await tenant_discovery(
            tenant_discovery_endpoint,
            verify=verify, proxies=proxies, timeout=timeout)

        return cls(
            authority_url=authority_url,
            validate_authority=validate_authority,
            verify=verify, proxies=proxies, timeout=timeout, openid_config=openid_config,
        )


async def retrieve_tenant_discovery_endpoint(url, authority_url, **kwargs):
    payload = await instance_discovery(url, **kwargs)
    return get_discovery_endpoint_from_payload(payload, authority_url)


async def instance_discovery(url, **kwargs):
    async with httpx.AsyncClient() as client:
        return (await client.get(
            'https://{}/common/discovery/instance'.format(
                WORLD_WIDE  # Historically using WORLD_WIDE. Could use self.instance too
                # See https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/4.0.0/src/Microsoft.Identity.Client/Instance/AadInstanceDiscovery.cs#L101-L103
                # and https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/4.0.0/src/Microsoft.Identity.Client/Instance/AadAuthority.cs#L19-L33
            ),
            params={'authorization_endpoint': url, 'api-version': '1.0'},
            **kwargs,
        )).json()


async def tenant_discovery(tenant_discovery_endpoint, **kwargs):
    # Returns Openid Configuration
    async with httpx.AsyncClient(**kwargs) as client:
        resp = await client.get(tenant_discovery_endpoint)
    payload = resp.json()
    if 'authorization_endpoint' in payload and 'token_endpoint' in payload:
        return payload
    raise MsalServiceError(status_code=resp.status_code, **payload)
