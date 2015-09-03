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

import com.sun.jna.platform.win32.Advapi32Util;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.security.UserDetails;
import org.sonar.plugins.ldap.windows.auth.IWindowsAuthProvider;
import org.sonar.plugins.ldap.windows.auth.WindowsAccount;
import org.sonar.plugins.ldap.windows.auth.WindowsPrincipal;

import static org.assertj.core.api.Assertions.assertThat;

;

public class WindowsAuthenticationHelperTest {
    private WindowsAuthenticationHelper authenticationHelper;

    @Before
    public void initialize() {
        authenticationHelper = new WindowsAuthenticationHelper();
    }

    @Test(expected = IllegalArgumentException.class)
    public void logonUserNullCheckUserName() {
        authenticationHelper.logonUser(null, "secret");
    }

    @Test(expected = IllegalArgumentException.class)
    public void logonUserNullCheckPassword() {
        authenticationHelper.logonUser("user", null);
    }

    @Test
    public void logonUserTests() {
        runLogonUserTest("domain", "user", "secret", true, Mockito.mock(WindowsPrincipal.class));
        runLogonUserTest("domain", "user", "secret", false, null);
        runLogonUserTest("domain", "user", "invalid-secret", true, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getUserDetailsNullCheck() {
        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper();
        authenticationHelper.getUserDetails(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getUserDetailsEmptyCheck() {
        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper();
        authenticationHelper.getUserDetails("");
    }


    @Test
    public void getUserDetailsTests() {
        runGetUserDetailsTest("domain\\user", true, "domain\\user");
        runGetUserDetailsTest("domain\\user", false, null);
    }

    private static void runLogonUserTest(String domainName, String userName, String password, boolean doesUserExistInDomain,
                                         final WindowsPrincipal expectedWindowsPrincipal) {
        int expectedInvocationCountLogonDomainUser = 0;
        if (doesUserExistInDomain) {
            expectedInvocationCountLogonDomainUser = 1;
        }


        IWindowsAuthProvider windowsAuthProvider = Mockito.mock(IWindowsAuthProvider.class);
        if (doesUserExistInDomain) {
            WindowsAccount account = Mockito.mock(WindowsAccount.class);
            Mockito.when(account.getDomainName()).thenReturn(domainName);
            Mockito.when(account.getName()).thenReturn(userName);
            Mockito.when(windowsAuthProvider.lookupAccount(getUserNameWithDomain(domainName, "\\", userName))).
                    thenReturn(account);
        }


        if (expectedWindowsPrincipal != null) {
            Mockito.when(windowsAuthProvider.logonDomainUser(domainName, userName, password))
                    .thenReturn(expectedWindowsPrincipal);
        }


        WindowsAuthenticationHelper windowsAuthenticationHelper = new WindowsAuthenticationHelper(windowsAuthProvider);

        WindowsPrincipal windowsPrincipal = windowsAuthenticationHelper.logonUser(getUserNameWithDomain(domainName, "\\", userName),
                password);

        if (expectedWindowsPrincipal == null) {
            assertThat(windowsPrincipal).isNull();
        } else {
            assertThat(windowsPrincipal).isEqualTo(expectedWindowsPrincipal);
        }
        Mockito.verify(windowsAuthProvider, Mockito.times(expectedInvocationCountLogonDomainUser)).
                logonDomainUser(domainName, userName, password);
    }

    private static void runGetUserDetailsTest(String userName, boolean doesUserExist, String expectedFqn) {
        Advapi32Util.Account account = null;
        if (expectedFqn != null && !expectedFqn.isEmpty()) {
            account = new Advapi32Util.Account();
            account.fqn = expectedFqn;
        }
        WindowsAccount windowsAccount = Mockito.mock(WindowsAccount.class);
        Mockito.when(windowsAccount.getFqn()).thenReturn(expectedFqn);

        IWindowsAuthProvider windowsAuthProvider = Mockito.mock(IWindowsAuthProvider.class);
        if (doesUserExist) {
            Mockito.when(windowsAuthProvider.lookupAccount(userName)).thenReturn(windowsAccount);
        }

        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper(windowsAuthProvider);

        UserDetails expectedUserDetails = null;
        if (expectedFqn != null && !expectedFqn.isEmpty()) {
            expectedUserDetails = new UserDetails();
            expectedUserDetails.setName(expectedFqn);
        }

        UserDetails userDetails = authenticationHelper.getUserDetails(userName);

        if (StringUtils.isBlank(expectedFqn)) {
            assertThat(userDetails).isNull();
        } else {
            assertThat(userDetails).isNotNull();
            assertThat(userDetails).isEqualToComparingFieldByField(expectedUserDetails);
        }
    }

    private static String getUserNameWithDomain(final String domainName, final String separator, final String userName) {
        String userNameWithDomain = "";
        if (domainName != null) {
            userNameWithDomain = domainName;
        }
        if (separator != null) {
            userNameWithDomain += separator;
        }
        if (userName != null) {
            userNameWithDomain += userName;
        }

        return userNameWithDomain;
    }

}
