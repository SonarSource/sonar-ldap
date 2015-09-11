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
package org.sonar.plugins.ldap.windows;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang.NullArgumentException;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.security.Authenticator;
import org.sonar.plugins.ldap.windows.auth.WindowsPrincipal;
import org.sonar.plugins.ldap.windows.stubs.HttpSessionStub;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsAuthenticatorTest {

    @Test(expected = NullArgumentException.class)
    public void constructorNullArgumentCheck() {
        WindowsAuthenticator authenticator = new WindowsAuthenticator(null);
    }

    @Test
    public void authenticateNullOrEmptyArgumentTests() {

        this.runAuthenticateNullOrEmptyArgumentTest(null, null, false);
        this.runAuthenticateNullOrEmptyArgumentTest("", null, false);
        this.runAuthenticateNullOrEmptyArgumentTest("user", null, false);
        this.runAuthenticateNullOrEmptyArgumentTest("user", "", false);
    }

    @Test
    public void authenticateNormalTests() {
        this.runAuthenticateTest("user", "secret", true);
        this.runAuthenticateTest("user", "invalid secret", false);
    }

    private void runAuthenticateTest(final String userName, final String password, boolean expectedIsUserAuthenticated) {
        WindowsPrincipal expectedWindowsPrincipal = null;
        WindowsAuthenticationHelper windowsAuthenticationHelper = Mockito.mock(WindowsAuthenticationHelper.class);
        if (expectedIsUserAuthenticated) {
            expectedWindowsPrincipal = Mockito.mock(WindowsPrincipal.class);
            Mockito.when(windowsAuthenticationHelper.logonUser(userName, password)).thenReturn(expectedWindowsPrincipal);
        }

        HttpServletRequest httpServletRequest = getHttpServletRequest();
        Authenticator.Context context = new Authenticator.Context(userName, password, httpServletRequest);
        WindowsAuthenticator authenticator = new WindowsAuthenticator(windowsAuthenticationHelper);

        boolean isUserAuthenticated = authenticator.doAuthenticate(context);
        WindowsPrincipal windowsPrincipal = (WindowsPrincipal) httpServletRequest.getSession().
                getAttribute(WindowsAuthenticationHelper.WINDOWS_PRINCIPAL);

        assertThat(isUserAuthenticated).isEqualTo(expectedIsUserAuthenticated);
        Mockito.verify(windowsAuthenticationHelper, Mockito.times(1)).logonUser(userName, password);
        if (expectedIsUserAuthenticated) {
            assertThat(windowsPrincipal).isEqualTo(expectedWindowsPrincipal);
        } else {
            assertThat(windowsPrincipal).isNull();
        }
    }

    private void runAuthenticateNullOrEmptyArgumentTest(final String userName, final String password,
                                                        boolean expectedIsUserAuthenticated) {
        HttpServletRequest httpServletRequest = getHttpServletRequest();
        Authenticator.Context context = new Authenticator.Context(userName, password, httpServletRequest);

        WindowsAuthenticationHelper windowsAuthenticationHelper = Mockito.mock(WindowsAuthenticationHelper.class);
        WindowsAuthenticator authenticator = new WindowsAuthenticator(windowsAuthenticationHelper);

        boolean isUserAuthenticated = authenticator.doAuthenticate(context);

        assertThat(isUserAuthenticated).isEqualTo(expectedIsUserAuthenticated);
        Mockito.verify(windowsAuthenticationHelper, Mockito.never()).logonUser(userName, password);
    }

    private HttpServletRequest getHttpServletRequest() {
        HttpSession httpSession = new HttpSessionStub();
        HttpServletRequest httpServletRequest = Mockito.mock(HttpServletRequest.class);
        Mockito.when(httpServletRequest.getSession()).thenReturn(httpSession);

        return httpServletRequest;
    }

}
