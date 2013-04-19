/*
 * Sonar LDAP Plugin
 * Copyright (C) 2009 SonarSource
 * dev@sonar.codehaus.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package org.sonar.plugins.ldap;

import com.google.common.base.Objects;
import org.apache.commons.lang.StringUtils;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;

/**
 * @author Evgeny Mandrikov
 */
public class LdapUserMapping {

    private static final String DEFAULT_OBJECT_CLASS = "inetOrgPerson";
    private static final String DEFAULT_LOGIN_ATTRIBUTE = "uid";
    private static final String DEFAULT_NAME_ATTRIBUTE = "cn";
    private static final String DEFAULT_EMAIL_ATTRIBUTE = "mail";
    private static final String DEFAULT_REQUEST = "(&(objectClass=inetOrgPerson)(uid={login}))";

    private final String baseDn;
    private final String request;
    private final String realNameAttribute;
    private final String emailAttribute;

    /**
     * Constructs mapping from Sonar settings.
     */
    public LdapUserMapping(Settings settings, String ldapIndex) {
        String usersBaseDn = settings.getString(ldapIndex + ".user.baseDn");
        if (usersBaseDn == null) {
            String realm = settings.getString(ldapIndex + ".realm");
            if (realm != null) {
                usersBaseDn = LdapAutodiscovery.getDnsDomainDn(realm);
            }
        }

        String objectClass = settings.getString(ldapIndex + ".user.objectClass");
        String loginAttribute = settings.getString(ldapIndex + ".user.loginAttribute");

        this.baseDn = usersBaseDn;
        this.realNameAttribute = StringUtils.defaultString(settings.getString(ldapIndex + ".user.realNameAttribute"), DEFAULT_NAME_ATTRIBUTE);
        this.emailAttribute = StringUtils.defaultString(settings.getString(ldapIndex + ".user.emailAttribute"), DEFAULT_EMAIL_ATTRIBUTE);

        String req;
        if (StringUtils.isNotBlank(objectClass) || StringUtils.isNotBlank(loginAttribute)) {
            objectClass = StringUtils.defaultString(objectClass, DEFAULT_OBJECT_CLASS);
            loginAttribute = StringUtils.defaultString(loginAttribute, DEFAULT_LOGIN_ATTRIBUTE);
            req = "(&(objectClass=" + objectClass + ")(" + loginAttribute + "={login}))";
            // For backward compatibility with plugin versions lower than 1.2
            LoggerFactory.getLogger(LdapGroupMapping.class)
                    .warn("Properties 'ldap.user.objectClass' and 'ldap.user.loginAttribute' are deprecated" +
                            " and should be replaced by single property 'ldap.user.request' with value: " + req);
        } else {
            req = StringUtils.defaultString(settings.getString(ldapIndex + ".user.request"), DEFAULT_REQUEST);
        }
        req = StringUtils.replace(req, "{login}", "{0}");
        this.request = req;
    }

    /**
     * Search for this mapping.
     */
    public LdapSearch createSearch(LdapContextFactory contextFactory, String username) {
        return new LdapSearch(contextFactory)
                .setBaseDn(getBaseDn())
                .setRequest(getRequest())
                .setParameters(username);
    }

    /**
     * Base DN. For example "ou=users,o=mycompany" or "cn=users" (Active Directory Server).
     */
    public String getBaseDn() {
        return baseDn;
    }

    /**
     * Request. For example:
     * <pre>
     * (&(objectClass=inetOrgPerson)(uid={0}))
     * (&(objectClass=user)(sAMAccountName={0}))
     * </pre>
     */
    public String getRequest() {
        return request;
    }

    /**
     * Real Name Attribute. For example "cn".
     */
    public String getRealNameAttribute() {
        return realNameAttribute;
    }

    /**
     * EMail Attribute. For example "mail".
     */
    public String getEmailAttribute() {
        return emailAttribute;
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this)
                .add("baseDn", getBaseDn())
                .add("request", getRequest())
                .add("realNameAttribute", getRealNameAttribute())
                .add("emailAttribute", getEmailAttribute())
                .toString();
    }

}
