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
package org.sonar.plugins.ldap.windows.auth;

import org.apache.commons.lang.StringUtils;
import org.sonar.api.ServerExtension;
import org.sonar.api.config.Settings;

public class WindowsAuthSettings implements ServerExtension {
  /**
   * Setting to return userId/login-id in lowercase in case of windows authentication mode.
   * This setting is already available in SonarQube.
   */
  public static final String SONAR_AUTHENTICATOR_LOGIN_DOWNCASE = "sonar.authenticator.downcase";

  private static final String SONAR_LDAP_WINDOWS = "sonar.ldap.windows";

  /**
   * Setting to return group names in lowercase in case of windows authentication mode.
   */
  public static final String SONAR_WINDOWS_GROUP_DOWNCASE = SONAR_LDAP_WINDOWS +".groups.downcase";

  /**
   * Settings to specify if Windows authentication is enabled or not.
   */
  public static final String SONAR_WINDOWS_AUTH = SONAR_LDAP_WINDOWS + ".auth";

  /**
   * Format of the userID returned by the plugin in Windows authentication mode.
   */
  public static final String SONAR_WINDOWS_USER_ID_FORMAT = SONAR_LDAP_WINDOWS + ".useridformat";

  /**
   * Format of the group name returned by plugin in Windows authentication mode.
   */
  public static final String SONAR_WINDOWS_USER_GROUP_FORMAT = SONAR_LDAP_WINDOWS + ".groupformat";

  /**
   * Authentication protocols supported by plugin in Windows authentication mode for Single Sign on (SSO)
   */
  public static final String SONAR_WINDOWS_AUTH_SSO_PROTOCOLS = SONAR_LDAP_WINDOWS + ".sso.protocols";

  public static final PrincipalFormat DEFAULT_SONAR_WINDOWS_USER_ID_FORMAT = PrincipalFormat.UPN;
  public static final PrincipalFormat DEFAULT_SONAR_WINDOWS_USER_GROUP_FORMAT = PrincipalFormat.UPN;
  public static final String DEFAULT_SONAR_LDAP_WINDOWS_AUTH = "true";
  public static final boolean DEFAULT_SONAR_AUTHENTICATOR_GROUP_DOWNCASE = true;
  public static final String DEFAULT_SONAR_WINDOWS_AUTH_SSO_PROTOCOLS = "NTLM";

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
    String sonarAuthenticatorGroupDownCase = StringUtils.defaultIfBlank(settings.getString(SONAR_WINDOWS_GROUP_DOWNCASE),
      Boolean.toString(DEFAULT_SONAR_AUTHENTICATOR_GROUP_DOWNCASE));

    return Boolean.parseBoolean(sonarAuthenticatorGroupDownCase);
  }

  /**
   *  Settings to specify if Windows authentication is enabled or not. By default, its value is "true".
   */
  public String getIsSonarLdapWindowsAuth() {
    return StringUtils.defaultIfBlank(settings.getString(SONAR_WINDOWS_AUTH), DEFAULT_SONAR_LDAP_WINDOWS_AUTH);
  }

  /**
   * Returns user-id format returned by the plugin in Windows Authentication mode. By default, the format is
   * {@link PrincipalFormat} UPN.
   */
  public PrincipalFormat getUserIdFormat() {
    return getPrincipalFormat(SONAR_WINDOWS_USER_ID_FORMAT, DEFAULT_SONAR_WINDOWS_USER_ID_FORMAT);
  }

  /**
   * Returns the user group name format returned by the plugin in Windows Authentication mode. By default, the format is
   * {@link PrincipalFormat} UPN.
   */
  public PrincipalFormat getUserGroupFormat() {
    return getPrincipalFormat(SONAR_WINDOWS_USER_GROUP_FORMAT, DEFAULT_SONAR_WINDOWS_USER_GROUP_FORMAT);
  }

  /**
   * Returns the authentication protocols (NTLM Negotiate) to be used by the plugin in Windows Authentication mode
   * single sign on. By default, protocol is NTLM.
   */
  public String getProtocols() {
    return StringUtils.defaultIfBlank(settings.getString(SONAR_WINDOWS_AUTH_SSO_PROTOCOLS), DEFAULT_SONAR_WINDOWS_AUTH_SSO_PROTOCOLS);
  }

  private PrincipalFormat getPrincipalFormat(String settingName, PrincipalFormat defaultPrincipalFormat) {
    PrincipalFormat principalFormat = defaultPrincipalFormat;

    String userIdFormatString = settings.getString(settingName);
    if (StringUtils.isNotBlank(userIdFormatString)) {
      principalFormat = Enum.valueOf(PrincipalFormat.class, userIdFormatString.toUpperCase());
    }

    return principalFormat;
  }
}
