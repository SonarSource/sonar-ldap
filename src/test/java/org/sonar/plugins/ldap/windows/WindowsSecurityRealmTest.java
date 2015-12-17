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
package org.sonar.plugins.ldap.windows;

import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import waffle.windows.auth.IWindowsAuthProvider;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsSecurityRealmTest {

  @Test
  public void normal() {
    WindowsAuthSettings settings = new WindowsAuthSettings(new Settings());
    IWindowsAuthProvider windowsAuthProvider = Mockito.mock(IWindowsAuthProvider.class);
    AdConnectionHelper adConnectionHelper = Mockito.mock(AdConnectionHelper.class);

    WindowsAuthenticationHelper windowsAuthenticationHelper = new WindowsAuthenticationHelper(settings, windowsAuthProvider, adConnectionHelper);
    WindowsSecurityRealm windowsSecurityRealm = new WindowsSecurityRealm(windowsAuthenticationHelper);

    assertThat(windowsSecurityRealm.getName()).isEqualTo("LDAP");
    assertThat(windowsSecurityRealm.doGetAuthenticator()).isInstanceOf(WindowsAuthenticator.class);
    assertThat(windowsSecurityRealm.getUsersProvider()).isInstanceOf(WindowsUsersProvider.class);
    assertThat(windowsSecurityRealm.getGroupsProvider()).isInstanceOf(WindowsGroupsProvider.class);
  }
}
