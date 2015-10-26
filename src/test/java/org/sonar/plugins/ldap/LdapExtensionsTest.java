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

import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.sonar.api.config.Settings;
import org.sonar.api.utils.System2;
import org.sonar.plugins.ldap.windows.WindowsAuthenticationHelper;
import org.sonar.plugins.ldap.windows.WindowsSecurityRealm;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import org.sonar.plugins.ldap.windows.auth.servlet.WindowsLogoutFilter;
import org.sonar.plugins.ldap.windows.sso.servlet.SsoAuthenticationFilter;
import org.sonar.plugins.ldap.windows.sso.servlet.SsoValidationFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class LdapExtensionsTest {
  @Test
  public void provideTests() {
    Settings settings = new Settings();
    LdapExtensions ldapExtensions = new LdapExtensions(settings);

    Object ldapExtensionsObject = ldapExtensions.provide();
    assertThat(ldapExtensionsObject).isNotNull();
  }

  @Test
  public void getExtensionsDefaultOnWindowsTests() {
    this.runGetExtensionsDefaultTest(true, this.getExpectedWindowsExtensions());
  }

  @Test
  public void getExtensionsDefaultOnNonWindowsOsTests() {
    this.runGetExtensionsDefaultTest(false, this.getExpectedLdapExtensions());
  }

  @Test
  public void getExtensionsForWindowsSecurity() {
    this.runGetExtensionsTest("true", true, this.getExpectedWindowsExtensions());
  }

  @Test
  public void getExtensionsForLdapRealm() {
    this.runGetExtensionsTest("ldap", false, this.getExpectedLdapExtensions());
    this.runGetExtensionsTest("", false, this.getExpectedLdapExtensions());
    this.runGetExtensionsTest(null, false, this.getExpectedLdapExtensions());
    this.runGetExtensionsTest("", true, this.getExpectedLdapExtensions());
    this.runGetExtensionsTest(null, true, this.getExpectedWindowsExtensions());
    this.runGetExtensionsTest("ldap", true, this.getExpectedLdapExtensions());
  }

  @Test(expected = IllegalArgumentException.class)
  public void getExtensionsThrowsException() {
    Settings settings = new Settings();
    settings.setProperty(WindowsAuthSettings.LDAP_WINDOWS_AUTH, "true");
    System2 system2 = mock(System2.class);
    when(system2.isOsWindows()).thenReturn(false);

    LdapExtensions ldapExtensions = new LdapExtensions(settings, system2);

    ldapExtensions.getExtensions();
  }

  private void runGetExtensionsDefaultTest(boolean isOperatingSystemWindows, List<Class<?>> expectedExtensions) {
    Settings settings = new Settings();
    System2 system2 = mock(System2.class);
    when(system2.isOsWindows()).thenReturn(isOperatingSystemWindows);
    LdapExtensions ldapExtensions = new LdapExtensions(settings, system2);

    List<Class<?>> extensions = ldapExtensions.getExtensions();

    assertThat(extensions).isNotNull().hasSameElementsAs(expectedExtensions);
  }

  private void runGetExtensionsTest(String windowsAuthSettingValue, boolean isOperatingSystemWindows, List<Class<?>> expectedExtensions) {
    Settings settings = new Settings();
    settings.setProperty(WindowsAuthSettings.LDAP_WINDOWS_AUTH, windowsAuthSettingValue);

    System2 system2 = mock(System2.class);
    when(system2.isOsWindows()).thenReturn(isOperatingSystemWindows);

    LdapExtensions ldapExtensions = new LdapExtensions(settings, system2);

    List<Class<?>> extensions = ldapExtensions.getExtensions();
    assertThat(extensions).isNotNull().hasSameElementsAs(expectedExtensions);
  }

  private List<Class<?>> getExpectedLdapExtensions() {
    return Arrays.asList(LdapRealm.class, LdapSettingsManager.class, LdapAutodiscovery.class);
  }

  private List<Class<?>> getExpectedWindowsExtensions() {
    return Arrays.asList(
      WindowsSecurityRealm.class,
      WindowsAuthenticationHelper.class,
      WindowsAuthSettings.class,
      SsoAuthenticationFilter.class,
      SsoValidationFilter.class,
      WindowsLogoutFilter.class);
  }
}
