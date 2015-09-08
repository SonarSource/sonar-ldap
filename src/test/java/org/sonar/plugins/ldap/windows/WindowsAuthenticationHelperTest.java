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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.security.UserDetails;
import org.sonar.plugins.ldap.windows.auth.IWindowsAuthProvider;
import org.sonar.plugins.ldap.windows.auth.WindowsAccount;
import org.sonar.plugins.ldap.windows.auth.WindowsPrincipal;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsAuthenticationHelperTest {
    private WindowsAuthenticationHelper authenticationHelper;

    @Before
    public void initialize() {
        IWindowsAuthProvider windowsAuthProvider = Mockito.mock(IWindowsAuthProvider.class);
        AdConnectionHelper adConnectionHelper = Mockito.mock(AdConnectionHelper.class);
        authenticationHelper = new WindowsAuthenticationHelper(windowsAuthProvider,
                adConnectionHelper);
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
        authenticationHelper.getUserDetails(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getUserDetailsEmptyCheck() {
        authenticationHelper.getUserDetails("");
    }

    @Test
    public void getUserDetailsTests() {
        UserDetails expectedUserDetails = new UserDetails();
        expectedUserDetails.setName("Full Name");
        expectedUserDetails.setEmail("abc@example.org");
        runGetUserDetailsTest("domain", "user", true, expectedUserDetails);
        runGetUserDetailsTest("domain", "user", false, null);
    }

    private static void runLogonUserTest(String domainName, String userName, String password,
                                         boolean doesUserExistInDomain, final WindowsPrincipal expectedWindowsPrincipal) {
        int expectedInvocationCountLogonDomainUser = 0;
        if (doesUserExistInDomain) {
            expectedInvocationCountLogonDomainUser = 1;
        }

        AdConnectionHelper adConnectionHelper = Mockito.mock(AdConnectionHelper.class);
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


        WindowsAuthenticationHelper windowsAuthenticationHelper = new WindowsAuthenticationHelper(windowsAuthProvider,
                adConnectionHelper);

        WindowsPrincipal windowsPrincipal = windowsAuthenticationHelper.logonUser(
                getUserNameWithDomain(domainName, "\\", userName), password);

        if (expectedWindowsPrincipal == null) {
            assertThat(windowsPrincipal).isNull();
        } else {
            assertThat(windowsPrincipal).isEqualTo(expectedWindowsPrincipal);
        }
        Mockito.verify(windowsAuthProvider, Mockito.times(expectedInvocationCountLogonDomainUser)).
                logonDomainUser(domainName, userName, password);
    }

    private static void runGetUserDetailsTest(String domainName, String userName, boolean doesUserExist,
                                              UserDetails expectedUserDetails) {
        IWindowsAuthProvider windowsAuthProvider = Mockito.mock(IWindowsAuthProvider.class);

        AdConnectionHelper adConnectionHelper = Mockito.mock(AdConnectionHelper.class);
        String userNameWithDomain = getUserNameWithDomain(domainName, "\\", userName);
        if (doesUserExist) {
            Map<String, String> attributesUserDetails = new HashMap<String, String>();
            attributesUserDetails.put(AdConnectionHelper.COMMON_NAME_ATTRIBUTE, expectedUserDetails.getName());
            attributesUserDetails.put(AdConnectionHelper.MAIL_ATTRIBUTE, expectedUserDetails.getEmail());

            Collection<String> attributeNames = new ArrayList<String>();
            attributeNames.add(AdConnectionHelper.COMMON_NAME_ATTRIBUTE);
            attributeNames.add(AdConnectionHelper.MAIL_ATTRIBUTE);

            Mockito.when(adConnectionHelper.getUserDetails(domainName, userName, attributeNames)).
                    thenReturn(attributesUserDetails);

            WindowsAccount windowsAccount = Mockito.mock(WindowsAccount.class);
            Mockito.when(windowsAccount.getDomainName()).thenReturn(domainName);
            Mockito.when(windowsAccount.getName()).thenReturn(userName);

            Mockito.when(windowsAuthProvider.lookupAccount(userNameWithDomain)).thenReturn(windowsAccount);
        }

        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper(windowsAuthProvider,
                adConnectionHelper);

        UserDetails userDetails = authenticationHelper.getUserDetails(userNameWithDomain);

        if (expectedUserDetails == null) {
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
