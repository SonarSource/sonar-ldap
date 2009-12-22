package org.sonar.plugins.ldap;

import com.teklabs.throng.integration.ldap.LdapHelper;
import org.sonar.api.security.LoginPasswordAuthenticator;

import javax.naming.NamingException;

/**
 * @author Evgeny Mandrikov
 */
public class LdapAuthenticator implements LoginPasswordAuthenticator {
    private LdapConfiguration configuration;

    public LdapAuthenticator(LdapConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void init() {
        try {
            configuration.getLdap().testConnection();
        } catch (NamingException e) {
            throw new RuntimeException("Unable to open LDAP connection", e);
        }
    }

    @Override
    public boolean authenticate(final String login, final String password) {
        try {
            return configuration.getLdap().authenticate(login, password);
        } catch (NamingException e) {
            LdapHelper.LOG.error("Unable to authenticate: " + login, e);
            return false;
        }
    }
}
