/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.plugins.ldap.windows.auth;

import org.apache.commons.lang.StringUtils;
import org.sonar.api.config.Settings;
import org.sonar.api.server.ServerSide;

@ServerSide
public class WindowsAuthSettings {
  /**
   * Setting to return userId/login-id in lowercase in case of windows authentication mode.
   * This setting is already available in SonarQube.
   */
  public static final String SONAR_AUTHENTICATOR_LOGIN_DOWNCASE = "sonar.authenticator.downcase";

  private static final String LDAP_WINDOWS = "ldap.windows";

  /**
   * Settings to specify if Windows authentication is enabled or not.
   */
  public static final String LDAP_WINDOWS_AUTH = LDAP_WINDOWS + ".auth";

  /**
   * Authentication protocols supported by plugin in Windows authentication mode for Single Sign on (SSO)
   */
  public static final String LDAP_WINDOWS_AUTH_SSO_PROTOCOLS = LDAP_WINDOWS + ".sso.protocols";

  /**
   * Setting to return group names in lowercase in case of windows authentication mode.
   */
  public static final String LDAP_WINDOWS_GROUP_DOWNCASE = LDAP_WINDOWS + ".group.downcase";

  /**
   * Setting to specify compatibility mode
   */
  public static final String LDAP_WINDOWS_COMPATIBILITY_MODE = LDAP_WINDOWS + ".compatibilityMode";

  /**
   * Setting to specify group-id attribute, which is used by plugin while returning user groups in compatibility mode
   */
  public static final String LDAP_GROUP_ID_ATTRIBUTE = "ldap.group.idAttribute";
  
  /**
   * Settings to specify real name attribute for a user
   */
  public static final String LDAP_WINDOWS_USER_REAL_NAME_ATTRIBUTE = LDAP_WINDOWS + ".user.realNameAttribute"; 

  public static final String DEFAULT_USER_REAL_NAME_ATTRIBUTE = "cn";
  public static final String DEFAULT_SONAR_LDAP_WINDOWS_AUTH = "true";
  public static final String DEFAULT_SONAR_WINDOWS_AUTH_SSO_PROTOCOLS = "NTLM";
  public static final boolean DEFAULT_WINDOWS_COMPATIBILITY_MODE = false;
  public static final boolean DEFAULT_SONAR_AUTHENTICATOR_GROUP_DOWNCASE = true;
  public static final String DEFAULT_LDAP_WINDOWS_GROUP_ID_ATTRIBUTE = "cn";

  private final Settings settings;

  public WindowsAuthSettings(Settings settings) {
    this.settings = settings;
  }

  /**
   * Returns true if sonar authentication is set to return userId in lowercase. By default, it is set to false.
   */
  public boolean getIsSonarAuthenticatorLoginDownCase() {
    return Boolean.parseBoolean(settings.getString(SONAR_AUTHENTICATOR_LOGIN_DOWNCASE));
  }

  /**
   * Returns true if sonar authentication is set to return group names in lowercase.  By default it is set to true.
   */
  public boolean getIsSonarAuthenticatorGroupDownCase() {
    String sonarAuthenticatorGroupDownCase = StringUtils.defaultIfBlank(settings.getString(LDAP_WINDOWS_GROUP_DOWNCASE),
      Boolean.toString(DEFAULT_SONAR_AUTHENTICATOR_GROUP_DOWNCASE));

    return Boolean.parseBoolean(sonarAuthenticatorGroupDownCase);
  }

  /**
   *  Settings to specify if Windows authentication is enabled or not. By default, its value is "true".
   */
  public String getIsSonarLdapWindowsAuth() {
    return StringUtils.defaultIfBlank(settings.getString(LDAP_WINDOWS_AUTH), DEFAULT_SONAR_LDAP_WINDOWS_AUTH);
  }

  /**
   * Settings to specify if Ldap Windows compatibility mode is enabled or not.  By default compatibility mode is disabled
   */
  public boolean getIsLdapWindowsCompatibilityModeEnabled() {
    String ldapWindowsCompatibilityMode = StringUtils.defaultIfBlank(settings.getString(LDAP_WINDOWS_COMPATIBILITY_MODE),
      Boolean.toString(DEFAULT_WINDOWS_COMPATIBILITY_MODE));

    return Boolean.parseBoolean(ldapWindowsCompatibilityMode);
  }

  /**
   * Settings to specify the groups id attribute. By default, its value is "cn"
   */
  public String getGroupIdAttribute() {
    return StringUtils.defaultIfBlank(settings.getString(LDAP_GROUP_ID_ATTRIBUTE), DEFAULT_LDAP_WINDOWS_GROUP_ID_ATTRIBUTE);
  }

  /**
   * Returns the authentication protocols (NTLM Negotiate) to be used by the plugin in Windows Authentication mode
   * single sign on. By default, protocol is NTLM.
   */
  public String getProtocols() {
    return StringUtils.defaultIfBlank(settings.getString(LDAP_WINDOWS_AUTH_SSO_PROTOCOLS), DEFAULT_SONAR_WINDOWS_AUTH_SSO_PROTOCOLS);
  }
  
  /**
   * Returns the specified value for the real name attribute. By default, it's value is "cn"
   */
  public String getLdapUserRealNameAttribute(){ 
      return StringUtils.defaultIfBlank(settings.getString(LDAP_WINDOWS_USER_REAL_NAME_ATTRIBUTE), DEFAULT_USER_REAL_NAME_ATTRIBUTE ); 
  }

}
