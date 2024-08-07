""" Toolkit for creating remote apps that enable sign in/up with cilogon.
1. Register you invenio instance to cilogon vi comanage registry and make sure it is configured appropriately,
   like In your comnage, set the callabck URI as
   "https://myinveniohost.com/oauth/authorized/cilogon/".
   Make user to grab the *Client ID* and *Client Secret* 

2. Add the following items to your configuration (``invenio.cfg``).
   The ``CilogonSettingsHelper`` class can be used to help with setting up
   the configuration values:

.. code-block:: python

        from invenio_oauthclient.contrib import cilogon 

        helper = cilogon.CilogonSettingsHelper(
        title="CILOGON JLAB",
        description="CILOGON Comanage Registry",
        base_url="https://cilogon.org/jlab",
        )

        # create the configuration for Keycloak
        # because the URLs usually follow a certain schema, the settings helper
        # can be used to more easily build the configuration values:
        OAUTHCLIENT_CILOGON_USER_INFO_FROM_ENDPOINT = helper.user_info_url
        OAUTHCLIENT_CILOGON_USER_INFO_URL = helper.user_info_url
        OAUTHCLIENT_CILOGON_OPENID_CONFIG_URL = helper.base_url+'/.well-known/openid-configuration'

        # Cilogon uses JWTs (https://jwt.io/) for their tokens, which
        # contain information about the target audience (AUD) which is cilient_id by default. 
        # verification of the expected AUD value can be configured with:
        OAUTHCLIENT_CILOGON_OPENID_VERIFY_AUD = True
        OAUTHCLIENT_CILOGON_OPENID_AUD = "client audience"(same as client ID usually)

        # enable/disable checking if the JWT signature has expired
        OAUTHCLIENT_CILOGON_OPENID__VERIFY_EXP = True

        # add CILOGON as external login providers to the dictionary of remote apps
        OAUTHCLIENT_REMOTE_APPS = dict(
        cilogon_openid=helper.remote_app,
        )

        # set the following configuration to True to automatically use the
        # user's email address as account email
        USERPROFILES_EXTEND_SECURITY_FORMS = True

   By default, the title will be displayed as label for the login button,
    for example ``Login with My organization``. The description will be
    displayed in the user account section.

3. Grab the *Client ID* and *Client Secret* from the 
   Comanage Registry and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

        CILOGON_APP_CREDENTIALS = dict(
            consumer_key='<CLIENT ID>',
            consumer_secret='<CLIENT SECRET>',
        )

4. Now go to ``CFG_SITE_SECURE_URL/oauth/login/cilogon/`` (e.g.
   https://localhost:5000/oauth/login/cilogon/) and log in.

5. After authenticating successfully, you should see cilogon listed under
   Linked accounts: https://localhost:5000/account/settings/linkedaccounts/
"""



from .handlers import (
    disconnect_handler,
    disconnect_rest_handler,
    info_handler,
    setup_handler,
)
from .settings import CilogonSettingsHelper

__all__ = (
    "disconnect_handler",
    "disconnect_rest_handler",
    "info_handler",
    "setup_handler",
    "CilogonSettingsHelper",
)
