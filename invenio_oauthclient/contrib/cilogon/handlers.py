# from .handlers import (
#     disconnect_handler,
#     disconnect_rest_handler,
#     info_handler,
#     setup_handler,
# )

from flask import Blueprint, session, g, flash, current_app, redirect, url_for
from flask_login import current_user
from invenio_db import db

from flask_principal import (
    AnonymousIdentity,
    RoleNeed,
    UserNeed,
    identity_changed,
    identity_loaded,
)

from invenio_oauthclient import current_oauthclient
from invenio_oauthclient.handlers.rest import response_handler
from invenio_oauthclient.handlers.utils import require_more_than_one_external_account
from invenio_oauthclient.models import RemoteAccount
from invenio_oauthclient.oauth import oauth_link_external_id, oauth_unlink_external_id
from invenio_oauthclient.errors import OAuthClientUnAuthorized

from datetime import datetime
from .helpers import get_user_info, _generate_config_prefix

OAUTHCLIENT_CILOGON_SESSION_KEY = "identity.cilogon_provides"

cilogon_oauth_blueprint = Blueprint("cilogon_oauth", __name__)


def extend_identity(identity, roles):
    """Extend identity with roles based on CILOGON groups."""
    provides = set([UserNeed(current_user.email)] + [RoleNeed(name) for name in roles])
    identity.provides |= provides
    key = current_app.config.get(
        "OAUTHCLIENT_CILOGON_SESSION_KEY",
        OAUTHCLIENT_CILOGON_SESSION_KEY,
    )
    session[key] = provides

def disconnect_identity(identity):
    """Disconnect identity from CILOGON groups."""
    session.pop("cern_resource", None)
    key = current_app.config.get(
        "OAUTHCLIENT_CILOGON_SESSION_KEY",
        OAUTHCLIENT_CILOGON_SESSION_KEY,
    )
    provides = session.pop(key, set())
    identity.provides -= provides

def info_serializer_handler(remote, resp, token_user_info, user_info=None, **kwargs):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :param token_user_info: The content of the authorization token response.
    :param user_info: The response of the `user info` endpoint.
    :returns: A dictionary with serialized user information.
    """
    # fill out the information required by
    # 'invenio-accounts' and 'invenio-userprofiles'.

    user_info = user_info or {}  # prevent errors when accessing None.get(...)

    email = token_user_info.get("email") or user_info["email"]
    full_name = token_user_info.get("name") or user_info.get("name")
    username = token_user_info.get("preferred_username") or user_info.get(
        "preferred_username"
    )
    cilogonid = token_user_info.get("sub") or user_info.get("sub")
    return {
        "user": {
            "active": True,
            "email": email,
            "profile": {
                "full_name": full_name,
                "username": username,
            },
            "preferences": {
                "visibility": "public",
                "email_visibility": "public",
            }
        },
        "external_id": cilogonid,
        "external_method": remote.name,
    }

def filter_groups(remote, groups):
    """ Filter groups from locall Allowed_ROLES.
    :param remote: The remote application.
    :param groups: List of groups to filter from <config_prefix>_ALLOWED_ROLES
    :retruns: A List of matching groups.
    """
    config_prefix = _generate_config_prefix(remote)
    valid_roles = current_app.config[f"{config_prefix}_ALLOWED_ROLES"]
    matching_groups = [group for group in groups if group in valid_roles]
    if not matching_groups:
        # Return an error if no matching groups are found
        raise OAuthClientUnAuthorized("User roles {0} are not one of {1}".format(str(groups), str(valid_roles)),
        remote,
        )
    return matching_groups

def get_groups(remote, account, group_names):
    """ Get groups from filter_groups and add as account extra data.
    :param remote: The remote application.
    :param account: The remote application.
    """
    roles = filter_groups(remote, group_names)
    updated = datetime.utcnow()
    account.extra_data.update(roles=roles, updated=updated.isoformat())
    return roles

def group_serializer_handler(remote, resp, token_user_info, user_info=None, **kwargs):
    """Retrieve remote account information for group for finding matching local groups.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    user_info = user_info or {}  # prevent errors when accessing None.get(...)
    group_names = token_user_info.get("isMemberOf") or user_info.get("isMemberOf")
    # check for matching group
    matching_groups = filter_groups(remote, group_names)
    groups_dict_list = []
    for group in matching_groups:
        group_dict = {
            "id" : group,
            "name": group,
            "description": "Group taken from CILOGON"
            }
        groups_dict_list.append(group_dict)
    return groups_dict_list


def group_handler(remote, resp):
    """Retrieve remote account information for finding matching local users.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    token_user_info, user_info = get_user_info(remote, resp)
    handlers = current_oauthclient.signup_handlers[remote.name]
    # `remote` param automatically injected via `make_handler` helper
    return handlers["groups_serializer"](resp, token_user_info, user_info)

def info_handler(remote, resp):
    """Retrieve remote account information for finding matching local users.

    :param remote: The remote application.
    :param resp: The response of the `authorized` endpoint.
    :returns: A dictionary with the user information.
    """
    token_user_info, user_info = get_user_info(remote, resp)
    handlers = current_oauthclient.signup_handlers[remote.name]
    # `remote` param automatically injected via `make_handler` helper
    return handlers["info_serializer"](resp, token_user_info, user_info)

def setup_handler(remote, token, resp):
    """Perform additional setup after the user has been logged in."""
    token_user_info, _ = get_user_info(remote, resp, from_token_only=True)

    with db.session.begin_nested():
        # fetch the user's cilogon ID (sub) and set it in extra_data
        cilogonid = token_user_info["sub"]
        token.remote_account.extra_data = {
            "cilogonid": cilogonid,
        }

        user = token.remote_account.user
        external_id = {"id": cilogonid, "method": remote.name}
        group_names = token_user_info.get("isMemberOf")

        roles = get_groups(remote, token.remote_account, group_names)
        assert not isinstance(g.identity, AnonymousIdentity)
        extend_identity(g.identity, roles)

        # link account with external cilogon ID
        oauth_link_external_id(user, external_id)

@require_more_than_one_external_account
def _disconnect(remote, *args, **kwargs):
    """Common logic for handling disconnection of remote accounts."""
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(
        user_id=current_user.get_id(), client_id=remote.consumer_key
    )

    cilogonid = account.extra_data.get("cilogonid")

    if cilogonid:
        external_id = {"id": cilogonid, "method": remote.name}

        oauth_unlink_external_id(external_id)

    if account:
        with db.session.begin_nested():
            account.delete()
    disconnect_identity(g.identity)

def disconnect_handler(remote, *args, **kwargs):
    """Handle unlinking of the remote account."""
    _disconnect(remote, *args, **kwargs)
    return redirect(url_for("invenio_oauthclient_settings.index"))

def disconnect_rest_handler(remote, *args, **kwargs):
    """Handle unlinking of the remote account."""
    _disconnect(remote, *args, **kwargs)
    rconfig = current_app.config["OAUTHCLIENT_REST_REMOTE_APPS"][remote.name]
    redirect_url = rconfig["disconnect_redirect_url"]
    return response_handler(remote, redirect_url)
