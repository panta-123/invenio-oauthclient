'''
This module requires some settings configured in your instance configuration. invenio.cfg
OAUTHCLIENT_REMOTE_APPS = {}  # configure external login providers
from invenio_oauthclient.contrib import cilogon as k
helper = k.cilogonOAuthSettingsHelper(
title="My Organzation",
description="Organization Comanage Registry",
base_url="https://cilogon.org/jlab",  # replace jlab with your comanage organization name
)

OAUTHCLIENT_CILOGON_OPENID_USER_INFO_FROM_ENDPOINT = helper.user_info_url
OAUTHCLIENT_CILOGON_OPENID_USER_INFO_URL = helper.user_info_url
OAUTHCLIENT_CILOGON_OPENID_OPENID_CONFIG_URL = helper.base_url+'/.well-known/openid-configuration'

        # Keycloak uses JWTs (https://jwt.io/) for their tokens, which
        # contain information about the target audience (AUD)
        # verification of the expected AUD value can be configured with:
OAUTHCLIENT_CILOGON_OPENID_VERIFY_AUD = True
OAUTHCLIENT_CILOGON_OPENID_AUD = "client audience"(same as client ID usually)

        # enable/disable checking if the JWT signature has expired
OAUTHCLIENT_CILOGON_OPENID__VERIFY_EXP = True

        # add CILOGON to the dictionary of remote apps
OAUTHCLIENT_REMOTE_APPS = dict(
cilogon_openid=helper.remote_app,
            # ...
)

        # set the following configuration to True to automatically use the
        # user's email address as account email
USERPROFILES_EXTEND_SECURITY_FORMS = True

#   By default, the title will be displayed as label for the login button,
#    for example ``Login with My organization``. The description will be
#    displayed in the user account section.
#
#3. Grab the *Client ID* and *Client Secret* from the client application in
#   Comanage Registry and add them to your instance configuration (``invenio.cfg``):
#
#   .. code-block:: python
#
CILOGON_APP_CREDENTIALS = dict(
    consumer_key="client_id",
    consumer_secret="client_secret",
)



'''



from .handlers import (
    disconnect_handler,
    disconnect_rest_handler,
    info_handler,
    setup_handler,
)
from .settings import CilogonOAuthSettingsHelper

__all__ = (
    "disconnect_handler",
    "disconnect_rest_handler",
    "info_handler",
    "setup_handler",
    "CilogonOAuthSettingsHelper",
)
