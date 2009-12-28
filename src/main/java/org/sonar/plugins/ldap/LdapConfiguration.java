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

import com.teklabs.throng.integration.ldap.Ldap;
import com.teklabs.throng.integration.ldap.LdapContextFactory;
import com.teklabs.throng.integration.ldap.LdapHelper;
import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.ServerExtension;

import java.net.UnknownHostException;

import static com.teklabs.throng.integration.ldap.Ldap.DEFAULT_LOGIN_ATTRIBUTE;
import static com.teklabs.throng.integration.ldap.Ldap.DEFAULT_USER_OBJECT_CLASS;
import static com.teklabs.throng.integration.ldap.LdapContextFactory.DEFAULT_AUTHENTICATION;
import static com.teklabs.throng.integration.ldap.LdapContextFactory.DEFAULT_FACTORY;

/**
 * @author Evgeny Mandrikov
 */
public class LdapConfiguration implements ServerExtension {
    private Configuration configuration;
    private Ldap ldap = null;

    /**
     * Creates new instance of LdapConfiguration.
     *
     * @param configuration configuration
     */
    public LdapConfiguration(Configuration configuration) {
        this.configuration = configuration;
    }

    public Ldap getLdap() {
        if (ldap == null) {
            ldap = newInstance();
        }
        return ldap;
    }

    private Ldap newInstance() {
        String realm = configuration.getString("ldap.realm", null);
        if (realm == null) {
            try {
                realm = LdapHelper.getDnsDomainName();
            } catch (UnknownHostException e) {
                LdapHelper.LOG.error("Unable to determine domain name", e);
            }
        }

        String ldapUrl = configuration.getString("ldap.url", null);
        if (ldapUrl == null) {
            ldapUrl = LdapHelper.getLdapServer(realm);
        }

        String baseDN = getComaDelimitedValue(configuration, "ldap.baseDn", null);
        if (baseDN == null && realm != null) {
            baseDN = LdapHelper.getDnsDomainDn(realm);
        }

        LdapContextFactory contextFactory = new LdapContextFactory(ldapUrl);
        contextFactory.setAuthentication(configuration.getString("ldap.authentication", DEFAULT_AUTHENTICATION));
        contextFactory.setFactory(configuration.getString("ldap.contextFactoryClass", DEFAULT_FACTORY));
        contextFactory.setUsername(getComaDelimitedValue(configuration, "ldap.bindDn", null));
        contextFactory.setPassword(configuration.getString("ldap.bindPassword", null));
        contextFactory.setRealm(realm);

        Ldap result = new Ldap(contextFactory);
        result.setBaseDN(baseDN);
        result.setUserObjectClass(getComaDelimitedValue(configuration, "ldap.userObjectClass", DEFAULT_USER_OBJECT_CLASS));
        result.setLoginAttribute(configuration.getString("ldap.loginAttribute", DEFAULT_LOGIN_ATTRIBUTE));

        if (LdapHelper.LOG.isInfoEnabled()) {
            LdapHelper.LOG.info("Url: " + contextFactory.getProviderUrl());
            LdapHelper.LOG.info("Authentication: " + contextFactory.getAuthentication());
            LdapHelper.LOG.info("ContextFactoryClass: " + contextFactory.getFactory());
            LdapHelper.LOG.info("BindDn: " + contextFactory.getUsername());
            LdapHelper.LOG.info("Realm: " + contextFactory.getRealm());

            LdapHelper.LOG.info("BaseDn: " + result.getBaseDN());
            LdapHelper.LOG.info("UserObjectClass: " + result.getUserObjectClass());
            LdapHelper.LOG.info("LoginAttribute: " + result.getLoginAttribute());
        }

        return result;
    }

    private static String getComaDelimitedValue(Configuration configuration, String key, String defaultValue) {
        String[] values = configuration.getStringArray(key);
        return values != null && values.length != 0 ? StringUtils.join(values, ",") : defaultValue;
    }

}
