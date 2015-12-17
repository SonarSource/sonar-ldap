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

import java.util.ArrayList;
import java.util.Collection;
import javax.servlet.http.HttpServletRequest;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.security.ExternalGroupsProvider;
import waffle.servlet.WindowsPrincipal;
import waffle.windows.auth.WindowsAccount;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class WindowsGroupsProviderTest {

  @Test(expected = NullPointerException.class)
  public void nullArgumentCheck() {
    new WindowsGroupsProvider(null);
  }

  @Test
  public void doGetGroupsTests() {
    Collection<WindowsAccount> groups = new ArrayList<>();
    WindowsAccount windowsAccount = Mockito.mock(WindowsAccount.class);
    when(windowsAccount.getFqn()).thenReturn("group1");
    groups.add(windowsAccount);

    Collection<String> expectedGroups = new ArrayList<>();
    expectedGroups.add("group1");

    this.runDoGetGroupsTest(true, false, null, null);
    this.runDoGetGroupsTest(false, false, null, null);

    this.runDoGetGroupsTest(false, true, new ArrayList<WindowsAccount>(), new ArrayList<String>());
    this.runDoGetGroupsTest(false, true, groups, expectedGroups);

    this.runDoGetGroupsTest(true, true, new ArrayList<WindowsAccount>(), new ArrayList<String>());
    this.runDoGetGroupsTest(true, true, groups, expectedGroups);
  }

  private void runDoGetGroupsTest(boolean isUserAuthenticatedByBasicAuth, boolean doesUserExist,
    Collection<WindowsAccount> windowsAccounts, Collection<String> expectedGroups) {
    WindowsPrincipal windowsPrincipal = null;
    int getUserGroupsInvCount = 0;
    if (doesUserExist) {
      windowsPrincipal = Mockito.mock(WindowsPrincipal.class);
      getUserGroupsInvCount = 1;
    }

    HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
    ExternalGroupsProvider.Context context = new ExternalGroupsProvider.Context(null, httpServletRequest);

    String windowsPrincipalKey = WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY;
    if (isUserAuthenticatedByBasicAuth) {
      windowsPrincipalKey = WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY;
    }

    WindowsAuthenticationHelper windowsAuthenticationHelper = Mockito.mock(WindowsAuthenticationHelper.class);
    when(windowsAuthenticationHelper.getWindowsPrincipal(httpServletRequest, windowsPrincipalKey)).thenReturn(windowsPrincipal);
    if (doesUserExist) {
      when(windowsAuthenticationHelper.getUserGroups(windowsPrincipal)).thenReturn(expectedGroups);
    }

    WindowsGroupsProvider groupsProvider = new WindowsGroupsProvider(windowsAuthenticationHelper);

    Collection<String> groups = groupsProvider.doGetGroups(context);

    if (expectedGroups == null) {
      assertThat(groups).isNull();
      verify(windowsAuthenticationHelper, Mockito.times(getUserGroupsInvCount)).getUserGroups(windowsPrincipal);

    } else {
      assertThat(groups).isNotNull().hasSameElementsAs(expectedGroups);
      verify(windowsAuthenticationHelper, Mockito.times(getUserGroupsInvCount)).getUserGroups(windowsPrincipal);
    }
  }
}
