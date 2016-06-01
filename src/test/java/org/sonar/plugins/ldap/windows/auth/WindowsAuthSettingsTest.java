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

import org.junit.Test;
import org.sonar.api.config.Settings;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsAuthSettingsTest {
  @Test
  public void defaults() {
    Settings settings = new Settings();
    WindowsAuthSettings windowsAuthSettings = new WindowsAuthSettings(settings);

    Settings settingsWithBlankSettings = new Settings()
      .setProperty(WindowsAuthSettings.SONAR_AUTHENTICATOR_LOGIN_DOWNCASE, "")
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_AUTH_SSO_PROTOCOLS, "")
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_AUTH, "")
      .setProperty(WindowsAuthSettings.LDAP_GROUP_ID_ATTRIBUTE, "")
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_COMPATIBILITY_MODE, "");
    WindowsAuthSettings windowsAuthSettingsWithBlankSettings = new WindowsAuthSettings(settingsWithBlankSettings);

    validateDefaultSettings(windowsAuthSettings);
    validateDefaultSettings(windowsAuthSettingsWithBlankSettings);
  }

  @Test
  public void customSettings() {
    boolean sonarAuthenticatorDownCase = false;
    boolean sonarAuthenticatorGroupDownCase = false;
    boolean sonarLdapWindowsCompatibilityMode = true;
    String sonarLdapWindowsAuth = "true";
    String sonarLdapWindowsGroupIdAttribute = "userPrincipalName";
    String protocols = "someProtocol1 someProtocol2";

    Settings settings = new Settings()
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_GROUP_DOWNCASE, Boolean.toString(sonarAuthenticatorGroupDownCase))
      .setProperty(WindowsAuthSettings.SONAR_AUTHENTICATOR_LOGIN_DOWNCASE, Boolean.toString(sonarAuthenticatorDownCase))
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_AUTH, sonarLdapWindowsAuth)
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_COMPATIBILITY_MODE, Boolean.toString(sonarLdapWindowsCompatibilityMode))
      .setProperty(WindowsAuthSettings.LDAP_GROUP_ID_ATTRIBUTE, sonarLdapWindowsGroupIdAttribute)
      .setProperty(WindowsAuthSettings.LDAP_WINDOWS_AUTH_SSO_PROTOCOLS, protocols);

    WindowsAuthSettings windowsAuthSettings = new WindowsAuthSettings(settings);

    assertThat(windowsAuthSettings.getIsSonarAuthenticatorGroupDownCase()).isEqualTo(sonarAuthenticatorGroupDownCase);
    assertThat(windowsAuthSettings.getIsSonarAuthenticatorLoginDownCase()).isEqualTo(sonarAuthenticatorDownCase);
    assertThat(windowsAuthSettings.getIsSonarLdapWindowsAuth()).isEqualTo(sonarLdapWindowsAuth);
    assertThat(windowsAuthSettings.getIsLdapWindowsCompatibilityModeEnabled()).isEqualTo(sonarLdapWindowsCompatibilityMode);
    assertThat(windowsAuthSettings.getGroupIdAttribute()).isEqualTo(sonarLdapWindowsGroupIdAttribute);
    assertThat(windowsAuthSettings.getProtocols()).isEqualTo(protocols);
  }

  private static void validateDefaultSettings(WindowsAuthSettings windowsAuthSettings) {
    assertThat(windowsAuthSettings.getIsSonarAuthenticatorGroupDownCase()).isEqualTo(WindowsAuthSettings.DEFAULT_SONAR_AUTHENTICATOR_GROUP_DOWNCASE);
    assertThat(windowsAuthSettings.getIsSonarAuthenticatorLoginDownCase()).isEqualTo(false);
    assertThat(windowsAuthSettings.getIsSonarLdapWindowsAuth()).isEqualTo(WindowsAuthSettings.DEFAULT_SONAR_LDAP_WINDOWS_AUTH);
    assertThat(windowsAuthSettings.getIsLdapWindowsCompatibilityModeEnabled()).isEqualTo(WindowsAuthSettings.DEFAULT_WINDOWS_COMPATIBILITY_MODE);
    assertThat(windowsAuthSettings.getGroupIdAttribute()).isEqualTo(WindowsAuthSettings.DEFAULT_LDAP_WINDOWS_GROUP_ID_ATTRIBUTE);
    assertThat(windowsAuthSettings.getProtocols()).isEqualTo(WindowsAuthSettings.DEFAULT_SONAR_WINDOWS_AUTH_SSO_PROTOCOLS);
  }
}
