#!/usr/bin/python3
"""
Certificate-based, app-only token provider for Azure AD Connector (Samba4).

Purpose
-------
Replaces the interactive device-code *user* token on the AAD Connect sync
path with an Entra **app registration + certificate** (client credentials).
No refresh token on disk, no "user xy with privileges z" — the private key
is the only standing credential.

Design
------
AADInternals.get_token(scopes) is called with hard-coded audiences:
    - "https://graph.windows.net/.default"      -> the two SOAP envelopes
                                                    (object sync + PHS + readback)
    - "https://graph.microsoft.com/.default"     -> directory reads, set_adsyncenabled
    - "https://proxy.cloudwebappproxy.net/..."   -> Seamless SSO (optional)

Rather than editing those call sites, this provider accepts a `scope_map`
so the operator can, from config, redirect the graph.windows.net audience to
whatever resource actually carries `ADSynchronization.ReadWrite.All`
(the Dec-2024 "Microsoft Entra AD Synchronization Service" app). That is the
single value the spike tunes.

Returns dicts throughout (named access), never tuples.
"""
import base64
import json
from msal import ConfidentialClientApplication

#Type Hinting
from collections.abc import Iterable
from typing import Any, TypedDict, cast


# The typedDict class was created by claude (AI) because i wanted to have a more precise typing for dict
# i expected dict[... , ...] but the ai returned this instead. Well in 6 months i will be
# gracefull i guess when i have to change somehting.
class TokenResult(TypedDict, total=False):
    """The subset of the MSAL client-credentials response this module reads.

    total=False because a failed grant returns error/error_description/
    correlation_id and no access_token, while a success returns the reverse.
    """
    access_token: str
    token_type: str
    expires_in: int
    ext_expires_in: int
    error: str
    error_description: str
    correlation_id: str


class AppCertTokenProvider:
    def __init__(
        self,
        *,
        tenant_id: str,
        client_id: str,
        private_key_path: str,
        thumbprint: str | None = None,
        public_cert_path: str | None = None,
        scope_map: dict[str, str] | None = None,
        proxies: dict[str, str] | None = None,
        verify: bool | str = True,
    ) -> None:
        """ready-to-use token source bound to a single app registration + certificate + tenant.

        Args:
            tenant_id (str): azure tenant ID
            client_id (str): azure application/client ID
            private_key_path (str): path to the private key created with openssl (x509)"
            ...-----BEGIN PRIVATE KEY-----... in PEM format"
            thumbprint (str | None, optional): the fingerprint of the key "A1B2C3D4E5F6...". Defaults to None.
            public_cert_path (str | None, optional): is public key certificate
            which will be sent through 'x5c' JWT header only for Per `specs 
            <https://tools.ietf.org/html/rfc7515#section-4.1.6>`_, "the certificate containing the public key
            corresponding to the key used to digitally sign the JWS MUST be the first certificate.  This MAY be
            followed byadditional certificates, with each subsequent certificate being the one used to certify
            the previous one." However, your certificate's issuer may use a different order. So, if your
            attempt ends up with an error AADSTS700027 - "The provided signature value did not match the
            expected signature value", you may try use only the leaf cert (in PEM/str format) instead
            subject name and issuer authentication to support cert auto rolls. Defaults to None.
            scope_map (dict[str, str] | None, optional): is the scope-rewrite table — a lookup that lets you 
            substitute one OAuth scope string for another at token-request time, without touching any of the 
            hard-coded scope strings inside AADInternals. keys and values are both plain strings (scope/audience
            strings like "https://graph.windows.net/.default"). None is also accepted as the argument. The 
            or {} immediately normalises it to an empty dict, so self.scope_map is always a dict[str, str] 
            internally — never None. That’s a deliberate guard so _map never has to null-check. 
            Defaults to None.
            proxies (dict[str, str] | None, optional): is the HTTP(S) proxy configuration passed through to the network 
            layer so token requests to Entra can go via a forward proxy — the same situation the tool already 
            handles for the sync traffic. default None → normalised to {} (no proxy).For reaching 
            login.microsoftonline.com only the "https" entry actually matters, since token endpoints are HTTPS.
            Defaults to None.
            verify (bool | str, optional): is the TLS certificate-verification control for the HTTPS calls to 
            Entra — passed through to MSAL, which hands it to requests.
            The two accepted types mean different things (same semantics as requests’ verify): bool
            True — verify the server cert against the system/certifi CA bundle. The default, and what you want.
            False — disable verification entirely. Don’t; it turns the TLS channel to Entra into something a MITM can
            sit on, and you’re shipping password hashes over it. The only “legitimate” use is throwaway debugging, 
            and even then prefer the path below.
            str — a filesystem path to a CA bundle (PEM). Use this when a firewall does SSL inspection and
            re-signs traffic: point verify at the firewall’s root CA so verification still happens, against 
            that CA. This is exactly the verify=/root/ca.crt case documented in the tool’s own README.
            So the valid set is: True, False, or "/path/to/ca.pem". Anything else (a tuple, an int, a Path 
            object) is wrong — and that’s the live bug we found: self.verify = True, in libsync.py makes it the tuple 
            (True,), which is not a valid verify value. It happens to be truthy so it hasn’t bitten yet, but it’s 
            type-incorrect and requests can behave unexpectedly with it. The integration.md fix drops the comma.
            . Defaults to True.
        """
        self.tenant_id: str = tenant_id
        self.client_id: str = client_id
        self.verify: bool | str = verify
        self.scope_map: dict[str, str] = scope_map or {}

        with open(private_key_path, "r", encoding="utf-8") as handle:
            private_key: str = handle.read()

        # Every value here is a str (key PEM, thumbprint, cert PEM), so the
        # dict is precisely dict[str, str] — no Any, no suppression needed.
        client_credential: dict[str, str] = {"private_key": private_key}
        if thumbprint:
            client_credential["thumbprint"] = thumbprint.replace(":", "").upper()
        if public_cert_path:
            with open(public_cert_path, "r", encoding="utf-8") as handle:
                # Enables SNI / x5c issuer-based auth; lets you rotate the cert
                # without re-registering the thumbprint.
                client_credential["public_certificate"] = handle.read()

        self.app: ConfidentialClientApplication = ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_credential,
            proxies=proxies or {},
            # MSAL types verify as bool, but at runtime it is handed straight to
            # requests, which also accepts a CA-bundle path str. Our bool | str
            # is the accurate type; the stub is too narrow.
            verify=verify,  # pyright: ignore[reportArgumentType]
        )

    def acquire(self, scopes: Iterable[str]) -> TokenResult:
        """Return the full MSAL result dict for the (mapped) scopes."""
        requested: list[str] = list(scopes)
        mapped: list[str] = [self.scope_map.get(scope, scope) for scope in requested]
        # acquire_token_for_client is annotated as a plain dict in MSAL; narrow
        # it to the keys we actually read.
        result: TokenResult = cast(TokenResult, self.app.acquire_token_for_client(scopes=mapped))
        if "access_token" not in result:
            raise RuntimeError(
                {
                    "requested_scopes": requested,
                    "mapped_scopes": mapped,
                    "error": result.get("error"),
                    "error_description": result.get("error_description"),
                    "correlation_id": result.get("correlation_id"),
                }
            )
        return result

    def get_token(self, scopes: Iterable[str]) -> str:
        """Drop-in replacement for AADInternals.get_token — returns the bearer string."""
        token: str | None = self.acquire(scopes).get("access_token")
        if token is None:  # unreachable: acquire() raises when access_token is absent
            raise RuntimeError("acquire() returned no access_token")
        return token


def decode_claims(access_token: str) -> dict[str, Any]:  # pyright: ignore[reportExplicitAny]
    """
    Decode (WITHOUT signature verification — diagnostics only) the JWT payload
    so the spike can confirm the token actually carries the sync app role.

    Claims are arbitrary JSON, so the value type is genuinely Any — this is the
    one place Any is honest rather than lazy.
    """
    payload_segment: str = access_token.split(".")[1]
    padding: str = "=" * (-len(payload_segment) % 4)
    decoded: bytes = base64.urlsafe_b64decode(payload_segment + padding)
    claims: dict[str, Any] = json.loads(decoded)  # pyright: ignore[reportExplicitAny]
    return claims