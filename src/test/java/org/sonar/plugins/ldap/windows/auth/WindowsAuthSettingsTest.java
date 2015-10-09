/*
 * SonarQube LDAP Plugin
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
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_AUTH_SSO_PROTOCOLS, "")
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_AUTH, "")
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_USER_ID_FORMAT, "")
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_USER_GROUP_FORMAT, "");
    WindowsAuthSettings windowsAuthSettingsWithBlankSettings = new WindowsAuthSettings(settingsWithBlankSettings);

    validateDefaultSettings(windowsAuthSettings);
    validateDefaultSettings(windowsAuthSettingsWithBlankSettings);
  }

  @Test
  public void customSettings() {
    boolean sonarAuthenticatorDownCase = false;
    boolean sonarAuthenticatorGroupDownCase = false;
    String sonarLdapWindowsAuth = "true";
    PrincipalFormat userIdFormat = PrincipalFormat.ULN;
    PrincipalFormat userGroupFormat = PrincipalFormat.ULN;
    String protocols = "someProtocol1 someProtocol2";

    Settings settings = new Settings()
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_GROUP_DOWNCASE, Boolean.toString(sonarAuthenticatorGroupDownCase))
      .setProperty(WindowsAuthSettings.SONAR_AUTHENTICATOR_LOGIN_DOWNCASE, Boolean.toString(sonarAuthenticatorDownCase))
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_AUTH, sonarLdapWindowsAuth)
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_USER_ID_FORMAT, userIdFormat.toString())
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_USER_GROUP_FORMAT, userGroupFormat.toString())
      .setProperty(WindowsAuthSettings.SONAR_WINDOWS_AUTH_SSO_PROTOCOLS, protocols);

    WindowsAuthSettings windowsAuthSettings = new WindowsAuthSettings(settings);

    assertThat(windowsAuthSettings.getIsSonarAuthenticatorGroupDownCase()).isEqualTo(sonarAuthenticatorGroupDownCase);
    assertThat(windowsAuthSettings.getIsSonarAuthenticatorLoginDownCase()).isEqualTo(sonarAuthenticatorDownCase);
    assertThat(windowsAuthSettings.getIsSonarLdapWindowsAuth()).isEqualTo(sonarLdapWindowsAuth);
    assertThat(windowsAuthSettings.getUserIdFormat()).isEqualTo(userIdFormat);
    assertThat(windowsAuthSettings.getUserGroupFormat()).isEqualTo(userGroupFormat);
    assertThat(windowsAuthSettings.getProtocols()).isEqualTo(protocols);

  }

  private static void validateDefaultSettings(WindowsAuthSettings windowsAuthSettings) {
    assertThat(windowsAuthSettings.getIsSonarAuthenticatorGroupDownCase()).isEqualTo(WindowsAuthSettings.DEFAULT_SONAR_AUTHENTICATOR_GROUP_DOWNCASE);
    assertThat(windowsAuthSettings.getIsSonarAuthenticatorLoginDownCase()).isEqualTo(false);
    assertThat(windowsAuthSettings.getIsSonarLdapWindowsAuth()).isEqualTo(WindowsAuthSettings.DEFAULT_SONAR_LDAP_WINDOWS_AUTH);
    assertThat(windowsAuthSettings.getUserIdFormat()).isEqualTo(WindowsAuthSettings.DEFAULT_SONAR_WINDOWS_USER_ID_FORMAT);
    assertThat(windowsAuthSettings.getUserGroupFormat()).isEqualTo(WindowsAuthSettings.DEFAULT_SONAR_WINDOWS_USER_GROUP_FORMAT);
    assertThat(windowsAuthSettings.getProtocols()).isEqualTo(WindowsAuthSettings.DEFAULT_SONAR_WINDOWS_AUTH_SSO_PROTOCOLS);

  }
}
