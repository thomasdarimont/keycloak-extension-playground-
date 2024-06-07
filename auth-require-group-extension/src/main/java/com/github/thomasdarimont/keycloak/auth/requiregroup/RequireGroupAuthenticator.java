package com.github.thomasdarimont.keycloak.auth.requiregroup;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Simple {@link Authenticator} that checks of a user is member of a given {@link GroupModel Group}.
 */
public class RequireGroupAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(RequireGroupAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {

        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();

        String groupPath = configModel.getConfig().get(RequireGroupAuthenticatorFactory.GROUP);
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        KeycloakSession session = context.getSession();

        String[] groups = groupPath.split(",");
        
		for (int i = 0; i < groups.length; i++) {
           if (isMemberOfGroup(session, realm, user, groups[i])) {
            LOG.warnf("Access grantes because of group membership. realm=%s username=%s groupPath=%s", realm.getName(), user.getUsername(), groups[i]);
            context.success();
            return;
            }
				}
        context.cancelLogin();

    }

    private boolean isMemberOfGroup(KeycloakSession session, RealmModel realm, UserModel user, String groupPath) {

        if (groupPath == null) {
            return false;
        }

        GroupModel group = KeycloakModelUtils.findGroupByPath(session, realm, groupPath);

        return user.isMemberOf(group);
    }



    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }
}
