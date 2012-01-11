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
package org.sonar.plugins.ldap.ng;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Objects;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.config.Settings;

/**
 * @author Evgeny Mandrikov
 */
public class LdapUserMapping {

  private static final String DEFAULT_USER_OBJECT_CLASS = "inetOrgPerson";
  private static final String DEFAULT_LOGIN_ATTRIBUTE = "uid";
  private static final String DEFAULT_NAME_ATTRIBUTE = "cn";
  private static final String DEFAULT_EMAIL_ATTRIBUTE = "mail";

  private final String baseDn;
  private final String userObjectClass;
  private final String loginAttribute;
  private final String realNameAttribute;
  private final String emailAttribute;

  @VisibleForTesting
  LdapUserMapping() {
    this.baseDn = "ou=users,dc=example,dc=org";
    this.userObjectClass = "inetOrgPerson";
    this.loginAttribute = "uid";
    this.realNameAttribute = "cn";
    this.emailAttribute = "mail";
  }

  /**
   * Constructs mapping from Sonar settings.
   */
  public LdapUserMapping(Settings settings) {
    // TODO maybe change legacy properties to be in consistence with Group Mapping
    String baseDn = settings.getString("ldap.baseDn");
    if (baseDn == null) {
      String realm = settings.getString("ldap.realm");
      if (realm != null) {
        baseDn = LdapAutodiscovery.getDnsDomainDn(realm);
      }
    }
    this.baseDn = baseDn;
    this.userObjectClass = StringUtils.defaultString(settings.getString("ldap.userObjectClass"), DEFAULT_USER_OBJECT_CLASS);
    this.loginAttribute = StringUtils.defaultString(settings.getString("ldap.loginAttribute"), DEFAULT_LOGIN_ATTRIBUTE);
    this.realNameAttribute = StringUtils.defaultString(settings.getString("ldap.user.realNameAttribute"), DEFAULT_NAME_ATTRIBUTE);
    this.emailAttribute = StringUtils.defaultString(settings.getString("ldap.user.emailAttribute"), DEFAULT_EMAIL_ATTRIBUTE);
  }

  /**
   * Search for this mapping.
   */
  public LdapSearch createSearch(LdapContextFactory contextFactory, String username) {
    String request = "(&(objectClass=" + getObjectClass() + ")(" + getLoginAttribute() + "={0}))";
    return new LdapSearch(contextFactory)
        .setBaseDn(getBaseDn())
        .setRequest(request)
        .setParameters(username);
  }

  /**
   * Base DN. For example "ou=users,o=mycompany" or "cn=users" (Active Directory Server).
   */
  public String getBaseDn() {
    return baseDn;
  }

  /**
   * Object Class. For example "inetOrgPerson" or "user" (Active Directory Server).
   */
  public String getObjectClass() {
    return userObjectClass;
  }

  /**
   * User ID Attribute. For example "uid" or "sAMAccountName" (Active Directory Server).
   */
  public String getLoginAttribute() {
    return loginAttribute;
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
        .add("objectClass", getObjectClass())
        .add("loginAttribute", getLoginAttribute())
        .add("realNameAttribute", getRealNameAttribute())
        .add("emailAttribute", getEmailAttribute())
        .toString();
  }

}
