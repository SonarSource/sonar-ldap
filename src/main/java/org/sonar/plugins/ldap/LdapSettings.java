/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009 SonarSource
 * sonarqube@googlegroups.com
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

import com.google.common.annotations.VisibleForTesting;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.config.Settings;
import org.sonar.api.server.ServerSide;

@ServerSide
public class LdapSettings {
  public static final String LDAP_PROPERTY_PREFIX = "ldap";
  @VisibleForTesting
  static final String AUTHENTICATION_METHOD_PROPERTY_SUFFIX = ".authentication";
  @VisibleForTesting
  static final String CONTEXT_FACTORY_CLASS_PROPERTY_SUFFIX = ".contextFactoryClass";
  @VisibleForTesting
  static final String LDAP_REALM_PROPERTY_SUFFIX = ".realm";
  @VisibleForTesting
  static final String LDAP_URL_PROPERTY_SUFFIX = ".url";
  @VisibleForTesting
  static final String LDAP_BIND_DN_PROPERTY_SUFFIX = ".bindDn";
  @VisibleForTesting
  static final String LDAP_BIND_PWD_PROPERTY_SUFFIX = ".bindPassword";

  @VisibleForTesting
  static final String DEFAULT_AUTHENTICATION = "simple";
  @VisibleForTesting
  static final String DEFAULT_LDAP_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
  @VisibleForTesting
  static final String LDAP_SERVERS_PROPERTY = LDAP_PROPERTY_PREFIX + ".servers";

  @VisibleForTesting
  static class User {
    public static final String BASE_DN_PROPERTY_SUFFIX = ".user.baseDn";
    public static final String REQUEST_PROPERTY_SUFFIX = ".user.request";

    public static final String REAL_NAME_ATTRIBUTE_PROPERTY_SUFFIX = ".user.realNameAttribute";
    public static final String EMAIL_ATTRIBUTE_PROPERTY_SUFFIX = ".user.emailAttribute";
    public static final String OBJECT_CLASS_PROPERTY_SUFFIX = ".user.objectClass";
    public static final String LOGIN_ATTRIBUTE_PROPERTY_SUFFIX = ".user.loginAttribute";

    public static final String DEFAULT_REQUEST = "(|(&(objectClass=inetOrgPerson)(uid={login}))(&(objectClass=user)(sAMAccountName={login})))";
    public static final String DEFAULT_REAL_NAME_ATTRIBUTE = "cn";
    public static final String DEFAULT_EMAIL_ATTRIBUTE = "mail";
    public static final String DEFAULT_OBJECT_CLASS = "inetOrgPerson";
    public static final String DEFAULT_LOGIN_ATTRIBUTE = "uid";

    private User() {
    }
  }

  @VisibleForTesting
  static class Group {
    public static final String BASE_DN_PROPERTY_SUFFIX = ".group.baseDn";
    public static final String REQUEST_PROPERTY_SUFFIX = ".group.request";
    public static final String OBJECT_CLASS_PROPERTY_SUFFIX = ".group.objectClass";
    public static final String MEMBER_ATTRIBUTE_PROPERTY_SUFFIX = ".group.memberAttribute";
    public static final String ID_ATTRIBUTE_PROPERTY_SUFFIX = ".group.idAttribute";

    public static final String DEFAULT_REQUEST = "(|(&(objectClass=groupOfUniqueNames)(uniqueMember={dn}))(&(objectClass=group)(member={dn})))";
    public static final String DEFAULT_OBJECT_CLASS = "groupOfUniqueNames";
    public static final String DEFAULT_MEMBER_ATTRIBUTE = "uniqueMember";
    public static final String DEFAULT_ID_ATTRIBUTE = "cn";

    private Group() {
    }
  }

  private final Settings settings;

  public LdapSettings(Settings settings) {
    this.settings = settings;
  }

  public String[] getLdapServerKeys() {
    return settings.getStringArray(LDAP_SERVERS_PROPERTY);
  }

  public String getLdapAuthenticationOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(settings.getString(settingsPrefix + AUTHENTICATION_METHOD_PROPERTY_SUFFIX),
      DEFAULT_AUTHENTICATION);
  }

  public String getLdapContextFactoryOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(settings.getString(settingsPrefix + CONTEXT_FACTORY_CLASS_PROPERTY_SUFFIX),
      DEFAULT_LDAP_CONTEXT_FACTORY);
  }

  public String getLdapRealm(String settingsPrefix) {
    return settings.getString(settingsPrefix + LDAP_REALM_PROPERTY_SUFFIX);
  }

  public String getLdapUrl(String settingsPrefix) {
    return settings.getString(settingsPrefix + LDAP_URL_PROPERTY_SUFFIX);
  }

  public String getLdapUrlKey(String settingsPrefix) {
    return settingsPrefix + LDAP_URL_PROPERTY_SUFFIX;
  }

  public String getBindUserNameDn(String settingsPrefix) {
    return settings.getString(settingsPrefix + LDAP_BIND_DN_PROPERTY_SUFFIX);
  }

  public String getBindPassword(String settingsPrefix) {
    return settings.getString(settingsPrefix + LDAP_BIND_PWD_PROPERTY_SUFFIX);
  }

  public String getUserBaseDn(String settingsPrefix) {
    return settings.getString(settingsPrefix + User.BASE_DN_PROPERTY_SUFFIX);
  }

  public String getUserObjectClassAttributeOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(getUserObjectClassAttribute(settingsPrefix),
      User.DEFAULT_OBJECT_CLASS);
  }

  public String getUserObjectClassAttribute(String settingsPrefix) {
    return settings.getString(settingsPrefix + User.OBJECT_CLASS_PROPERTY_SUFFIX);
  }

  public String getUserLoginAttributeOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(getUserLoginAttribute(settingsPrefix), User.DEFAULT_LOGIN_ATTRIBUTE);
  }

  public String getUserLoginAttribute(String settingsPrefix) {
    return settings.getString(settingsPrefix + User.LOGIN_ATTRIBUTE_PROPERTY_SUFFIX);
  }

  public String getUserRealNameAttributeOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(settings.getString(settingsPrefix + User.REAL_NAME_ATTRIBUTE_PROPERTY_SUFFIX),
      User.DEFAULT_REAL_NAME_ATTRIBUTE);
  }

  public String getUserEmailAttributeOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(settings.getString(settingsPrefix + User.EMAIL_ATTRIBUTE_PROPERTY_SUFFIX),
      User.DEFAULT_EMAIL_ATTRIBUTE);
  }

  public String getUserRequestOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(settings.getString(settingsPrefix + User.REQUEST_PROPERTY_SUFFIX),
      User.DEFAULT_REQUEST);
  }

  public String getUserGroupRequestOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(settings.getString(settingsPrefix + Group.REQUEST_PROPERTY_SUFFIX),
      Group.DEFAULT_REQUEST);
  }

  public String getUserGroupBaseDn(String settingsPrefix) {
    return settings.getString(settingsPrefix + Group.BASE_DN_PROPERTY_SUFFIX);
  }

  public String getUserGroupObjectClass(String settingsPrefix) {
    return settings.getString(settingsPrefix + Group.OBJECT_CLASS_PROPERTY_SUFFIX);
  }

  public String getUserGroupObjectClassOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(getUserGroupObjectClass(settingsPrefix),
      Group.DEFAULT_OBJECT_CLASS);
  }

  public String getUserGroupMemberAttribute(String settingsPrefix) {
    return settings.getString(settingsPrefix + Group.MEMBER_ATTRIBUTE_PROPERTY_SUFFIX);
  }

  public String getUserGroupMemberAttributeOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(getUserGroupMemberAttribute(settingsPrefix),
      Group.DEFAULT_MEMBER_ATTRIBUTE);
  }

  public String getUserGroupIdAttributeOrDefault(String settingsPrefix) {
    return StringUtils.defaultString(settings.getString(settingsPrefix + Group.ID_ATTRIBUTE_PROPERTY_SUFFIX),
      Group.DEFAULT_ID_ATTRIBUTE);
  }

  public boolean hasKey(String key) {
    return settings.hasKey(key);
  }

  public boolean isAutoDiscoveryEnabled() {
    return this.getLdapUrl(LDAP_PROPERTY_PREFIX) == null &&
      this.getLdapRealm(LDAP_PROPERTY_PREFIX) != null;
  }
}
