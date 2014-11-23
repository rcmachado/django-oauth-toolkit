# coding: utf-8
from __future__ import unicode_literals, absolute_import

import json
import logging

from oauthlib.grant_types.base import GrantTypeBase
from oauthlib import errors
from oauthlib.request_validator import RequestValidator

log = logging.getLogger(__name__)


class FacebookGrant(GrantTypeBase):
    def __init__(self, request_validator=None, refresh_token=True):
        """
        If the refresh_token keyword argument is False, do not return
        a refresh token in the response.
        """
        self.request_validator = request_validator or RequestValidator()
        self.refresh_token = refresh_token

    def create_token_response(self, request, token_handler):
        """Return token or error in json format.

        If the access token request is valid and authorized, the
        authorization server issues an access token and optional refresh
        token as described in `Section 5.1`_.  If the request failed client
        authentication or is invalid, the authorization server returns an
        error response as described in `Section 5.2`_.

        .. _`Section 5.1`: http://tools.ietf.org/html/rfc6749#section-5.1
        .. _`Section 5.2`: http://tools.ietf.org/html/rfc6749#section-5.2
        """
        headers = {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
        }
        try:
            if self.request_validator.client_authentication_required(request):
                log.debug('Authenticating client, %r.', request)
                if not self.request_validator.authenticate_client(request):
                    log.debug('Client authentication failed, %r.', request)
                    raise errors.InvalidClientError(request=request)
            elif not self.request_validator.authenticate_client_id(request.client_id, request):
                log.debug('Client authentication failed, %r.', request)
                raise errors.InvalidClientError(request=request)
            log.debug('Validating access token request, %r.', request)
            self.validate_token_request(request)
        except errors.OAuth2Error as e:
            log.debug('Client error in token request, %s.', e)
            return headers, e.json, e.status_code

        token = token_handler.create_token(request, self.refresh_token)
        log.debug('Issuing token %r to client id %r (%r) and username %s.',
                  token, request.client_id, request.client, request.username)
        return headers, json.dumps(token), 200

    def validate_token_request(self, request):
        """
        The client makes a request to the token endpoint by adding the
        following parameters using the "application/x-www-form-urlencoded"
        format per Appendix B with a character encoding of UTF-8 in the HTTP
        request entity-body:

        grant_type
                REQUIRED.  Value MUST be set to "password".

        username
                REQUIRED.  The resource owner username.

        password
                REQUIRED.  The resource owner password.

        scope
                OPTIONAL.  The scope of the access request as described by
                `Section 3.3`_.

        If the client type is confidential or the client was issued client
        credentials (or assigned other authentication requirements), the
        client MUST authenticate with the authorization server as described
        in `Section 3.2.1`_.

        The authorization server MUST:

        o  require client authentication for confidential clients or for any
            client that was issued client credentials (or with other
            authentication requirements),

        o  authenticate the client if client authentication is included, and

        o  validate the resource owner password credentials using its
            existing password validation algorithm.

        Since this access token request utilizes the resource owner's
        password, the authorization server MUST protect the endpoint against
        brute force attacks (e.g., using rate-limitation or generating
        alerts).

        .. _`Section 3.3`: http://tools.ietf.org/html/rfc6749#section-3.3
        .. _`Section 3.2.1`: http://tools.ietf.org/html/rfc6749#section-3.2.1
        """
        for param in ('grant_type', 'access_token'):
            if not getattr(request, param):
                raise errors.InvalidRequestError(
                    'Request is missing %s parameter.' % param, request=request)

        for param in ('grant_type', 'access_otken', 'scope'):
            if param in request.duplicate_params:
                raise errors.InvalidRequestError(description='Duplicate %s parameter.' % param, request=request)

        # This error should rarely (if ever) occur if requests are routed to
        # grant type handlers based on the grant_type parameter.
        if not request.grant_type == 'facebook':
            raise errors.UnsupportedGrantTypeError(request=request)

        log.debug('Validating facebook user %s.', request.access_token)
        if not self.request_validator.validate_facebook_user(
            request.access_token, request.client, request):
            raise errors.InvalidGrantError(
                'Invalid credentials given.', request=request)
        else:
            if not hasattr(request.client, 'client_id'):
                raise NotImplementedError(
                    'Validate user must set the '
                    'request.client.client_id attribute '
                    'in authenticate_client.')
        log.debug('Authorizing access to user %r.', request.user)

        # Ensure client is authorized use of this grant type
        self.validate_grant_type(request)

        if request.client:
            request.client_id = request.client_id or request.client.client_id
        self.validate_scopes(request)
