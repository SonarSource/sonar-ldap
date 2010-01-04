/*
 * Copyright (C) 2009
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
