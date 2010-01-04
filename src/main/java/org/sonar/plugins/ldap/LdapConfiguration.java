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
