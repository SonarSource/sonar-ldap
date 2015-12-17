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

import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.NullArgumentException;
import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.security.Authenticator;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthTestHelper;
import waffle.servlet.WindowsPrincipal;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsAuthenticatorTest {

  @Test(expected = NullArgumentException.class)
  public void constructorNullArgumentCheck() {
    WindowsAuthenticator authenticator = new WindowsAuthenticator(null);
  }

  @Test
  public void doAuthenticateServletRequestBasedTests() {

    this.runDoAuthenticateTest(null, null, true);
    this.runDoAuthenticateTest("", null, false);
    this.runDoAuthenticateTest("user", null, false);
    this.runDoAuthenticateTest("user", "", true);
    this.runDoAuthenticateTest("", "secret", false);
    this.runDoAuthenticateTest(null, "secret", true);
  }

  @Test
  public void doAuthenticateUserNamePasswordTests() {
    this.runDoAuthenticateTest("user", "secret", true);
    this.runDoAuthenticateTest("user", "invalid secret", false);
  }

  private void runDoAuthenticateTest(final String userName, final String password, boolean expectedIsUserAuthenticated) {

    if (StringUtils.isNotBlank(userName) && StringUtils.isNotBlank(password)) {
      runDoAuthenticateUserNamePasswordTests(userName, password, expectedIsUserAuthenticated);
    } else {
      runDoAuthenticateServletRequestBasedTests(userName, password, expectedIsUserAuthenticated);
    }
  }

  private void runDoAuthenticateServletRequestBasedTests(String userName, String password, boolean expectedIsUserAuthenticated) {
    HttpServletRequest httpServletRequest = WindowsAuthTestHelper.getHttpServletRequest();
    Authenticator.Context context = new Authenticator.Context(userName, password, httpServletRequest);

    WindowsAuthenticationHelper windowsAuthenticationHelper = Mockito.mock(WindowsAuthenticationHelper.class);
    Mockito.when(windowsAuthenticationHelper.isUserSsoAuthenticated(httpServletRequest)).thenReturn(expectedIsUserAuthenticated);

    WindowsAuthenticator authenticator = new WindowsAuthenticator(windowsAuthenticationHelper);

    boolean isUserAuthenticated = authenticator.doAuthenticate(context);

    assertThat(httpServletRequest.getSession().getAttribute(WindowsAuthenticationHelper.BASIC_AUTH_PRINCIPAL_KEY)).isNull();
    assertThat(isUserAuthenticated).isEqualTo(expectedIsUserAuthenticated);
    Mockito.verify(windowsAuthenticationHelper, Mockito.times(1)).isUserSsoAuthenticated(httpServletRequest);
  }

  private void runDoAuthenticateUserNamePasswordTests(String userName, String password, boolean expectedIsUserAuthenticated) {
    WindowsPrincipal expectedWindowsPrincipal = null;
    WindowsAuthenticationHelper windowsAuthenticationHelper = Mockito.mock(WindowsAuthenticationHelper.class);
    if (expectedIsUserAuthenticated) {
      expectedWindowsPrincipal = Mockito.mock(WindowsPrincipal.class);
    }

    Mockito.when(windowsAuthenticationHelper.logonUser(userName, password)).thenReturn(expectedWindowsPrincipal);

    HttpServletRequest httpServletRequest = WindowsAuthTestHelper.getHttpServletRequest();
    Authenticator.Context context = new Authenticator.Context(userName, password, httpServletRequest);
    WindowsAuthenticator authenticator = new WindowsAuthenticator(windowsAuthenticationHelper);

    boolean isUserAuthenticated = authenticator.doAuthenticate(context);

    assertThat(isUserAuthenticated).isEqualTo(expectedIsUserAuthenticated);
    if(expectedIsUserAuthenticated) {
      Mockito.verify(windowsAuthenticationHelper, Mockito.times(1)).setWindowsPrincipalForBasicAuth(context.getRequest(), expectedWindowsPrincipal);
    }else{
      Mockito.verify(windowsAuthenticationHelper, Mockito.times(0)).setWindowsPrincipalForBasicAuth(context.getRequest(), expectedWindowsPrincipal);
    }

    assertThat(httpServletRequest.getSession().getAttribute(WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY)).isNull();
    Mockito.verify(windowsAuthenticationHelper, Mockito.times(1)).logonUser(userName, password);
  }

}
