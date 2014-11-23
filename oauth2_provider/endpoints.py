# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""
from __future__ import absolute_import, unicode_literals

from oauthlib.oauth2 import AuthorizationCodeGrant
from oauthlib.oauth2 import ImplicitGrant
from oauthlib.oauth2 import ResourceOwnerPasswordCredentialsGrant
from oauthlib.oauth2 import ClientCredentialsGrant
from oauthlib.oauth2 import RefreshTokenGrant

from oauthlib.oauth2 import BearerToken

from oauthlib.oauth2 import AuthorizationEndpoint
from oauthlib.oauth2 import TokenEndpoint
from oauthlib.oauth2 import ResourceEndpoint
from oauthlib.oauth2 import RevocationEndpoint

from .facebook_grant_type import FacebookGrant


class Server(AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint,
             RevocationEndpoint):

    """An all-in-one endpoint featuring all four major grant types."""

    def __init__(self, request_validator, token_expires_in=None,
                 token_generator=None, refresh_token_generator=None,
                 *args, **kwargs):
        """Construct a new all-grants-in-one server.

        :param request_validator: An implementation of
                                  oauthlib.oauth2.RequestValidator.
        :param token_expires_in: An int or a function to generate a token
                                 expiration offset (in seconds) given a
                                 oauthlib.common.Request object.
        :param token_generator: A function to generate a token from a request.
        :param refresh_token_generator: A function to generate a token from a
                                        request for the refresh token.
        :param kwargs: Extra parameters to pass to authorization-,
                       token-, resource-, and revocation-endpoint constructors.
        """
        auth_grant = AuthorizationCodeGrant(request_validator)
        implicit_grant = ImplicitGrant(request_validator)
        password_grant = ResourceOwnerPasswordCredentialsGrant(
            request_validator)
        facebook_grant = FacebookGrant(request_validator)
        credentials_grant = ClientCredentialsGrant(request_validator)
        refresh_grant = RefreshTokenGrant(request_validator)
        bearer = BearerToken(request_validator, token_generator,
                             token_expires_in, refresh_token_generator)
        AuthorizationEndpoint.__init__(self, default_response_type='code',
                                       response_types={
                                           'code': auth_grant,
                                           'token': implicit_grant,
                                       },
                                       default_token_type=bearer)
        TokenEndpoint.__init__(self, default_grant_type='authorization_code',
                               grant_types={
                                   'authorization_code': auth_grant,
                                   'password': password_grant,
                                   'facebook': facebook_grant,
                                   'client_credentials': credentials_grant,
                                   'refresh_token': refresh_grant,
                               },
                               default_token_type=bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                                  token_types={'Bearer': bearer})
        RevocationEndpoint.__init__(self, request_validator)
