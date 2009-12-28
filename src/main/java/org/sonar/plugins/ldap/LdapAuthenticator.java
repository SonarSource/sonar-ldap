/*
 * Sonar, open source software quality management tool.
 * Copyright (C) 2009 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * Sonar is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * Sonar is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with Sonar; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package org.sonar.plugins.ldap;

import com.teklabs.throng.integration.ldap.LdapHelper;
import org.sonar.api.security.LoginPasswordAuthenticator;

import javax.naming.NamingException;

/**
 * @author Evgeny Mandrikov
 */
public class LdapAuthenticator implements LoginPasswordAuthenticator {
    private LdapConfiguration configuration;

    /**
     * Creates a new instance of LdapAuthenticator with specified configuration.
     *
     * @param configuration LDAP configuration
     */
    public LdapAuthenticator(LdapConfiguration configuration) {
        this.configuration = configuration;
    }

    public void init() {
        try {
            configuration.getLdap().testConnection();
        } catch (NamingException e) {
            throw new RuntimeException("Unable to open LDAP connection", e);
        }
    }

    public boolean authenticate(final String login, final String password) {
        try {
            return configuration.getLdap().authenticate(login, password);
        } catch (NamingException e) {
            LdapHelper.LOG.error("Unable to authenticate: " + login, e);
            return false;
        }
    }
}
