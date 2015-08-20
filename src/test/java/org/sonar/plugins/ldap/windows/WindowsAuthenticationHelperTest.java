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
import com.sun.jna.platform.win32.Netapi32Util;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinBase;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.security.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;

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
    public void logonUserForInvalidUserNameFormatTests() {
        runLogonUserTest(null, "\\", "", "secret", false, false, false);
        runLogonUserTest(null, "\\", null, "secret", false, false, false);
        runLogonUserTest("", "\\", null, "secret", false, false, false);
        runLogonUserTest("", "\\", "", "secret", false, false, false);
        runLogonUserTest("user", "@", "domain", "secret", false, false, false);
        runLogonUserTest("user@domain", "", "", "secret", false, false, false);
        runLogonUserTest("domain", "\\", "user\\other-format", "secret", false, false, false);
    }

    @Test
    public void logonUserForValidUserNameTests() {
        runLogonUserTest("domain", "\\", "user", "secret", true, true, true);
        runLogonUserTest("domain", "\\", "user", "invalid-secret", true, true, false);
    }

    @Test
    public void logonUserWhenAccountLookupReturnsNull() {
        runLogonUserTest("domain", "\\", "invalidUser", "secret", true, false, false);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getGroupsNullArgumentCheck() {
        authenticationHelper.getGroups(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getGroupsBlankArgumentCheck() {
        authenticationHelper.getGroups("");
    }

    @Test
    public void getGroupsInvalidUserName() {
        runGetGroupsTest(null, "\\", "", false, false, null);
        runGetGroupsTest(null, "\\", null, false, false, null);
        runGetGroupsTest("", "\\", null, false, false, null);
        runGetGroupsTest("", "\\", "", false, false, null);
        runGetGroupsTest("user", "@", "domain", false, false, null);
        runGetGroupsTest("user@domain", "", "", false, false, null);
        runGetGroupsTest("domain", "\\", "user\\other-format", false, false, null);
    }

    @Test
    public void getGroupsWhenAccountLookupReturnsNull() {
        runGetGroupsTest("domain", "\\", "otherUser", true, false, null);
    }

    @Test
    public void getGroupsForValidUserNameTests() {

        DomainGroup domainGroup1 = new DomainGroup();
        domainGroup1.setDomainName("Domain1");
        domainGroup1.setGroupName("Group1");

        DomainGroup domainGroup2 = new DomainGroup();
        domainGroup2.setDomainName("Domain1");
        domainGroup2.setGroupName("Group2");

        DomainGroup[] userWithNoDomainGroup = new DomainGroup[]{};
        DomainGroup[] userWithOneDomainGroup = new DomainGroup[]{domainGroup1};
        DomainGroup[] userWithTwoDomainGroups = new DomainGroup[]{domainGroup1, domainGroup2};

        runGetGroupsTest("Domain1", "\\", "userWithNoDomainGroup", true, true, userWithNoDomainGroup);
        runGetGroupsTest("Domain1", "\\", "userWithOneGroup", true, true, userWithOneDomainGroup);
        runGetGroupsTest("Domain1", "\\", "userWithTwoDomainGroups", true, true, userWithTwoDomainGroups);
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
    public void getUserDetailsForValidUserNamePatternTests() {
        runGetUserDetailsForValidUserNameTest("domain\\user", "domain\\user");
        runGetUserDetailsForValidUserNameTest("domain\\invalidUser", null);
    }

    @Test
    public void getUserDetailsWhenGetAccountByNameThrowsExceptionTest() {
        Win32PlatformWrapper win32PlatformWrapper = Mockito.mock(Win32PlatformWrapper.class);
        Win32Exception win32Exception = Mockito.mock(Win32Exception.class);
        Mockito.when(win32Exception.getMessage()).thenReturn("Win32Exception occurred");
        Mockito.when(win32PlatformWrapper.getAccountByName(null, "domain\\userName")).thenThrow(win32Exception);

        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper(win32PlatformWrapper);

        Mockito.verify(win32Exception, Mockito.times(1)).getMessage();
        assertThat(authenticationHelper.getUserDetails("domain\\userName")).isNull();
        Mockito.verify(win32PlatformWrapper, Mockito.never()).getUserGroups("domain", "userName");
        Mockito.verify(win32PlatformWrapper, Mockito.times(1)).getAccountByName(null, "domain\\userName");
    }

    @Test
    public void getUserDetailsWhenGetAccountByNameReturnsNullTest() {
        Win32PlatformWrapper win32PlatformWrapper = Mockito.mock(Win32PlatformWrapper.class);
        Mockito.when(win32PlatformWrapper.getAccountByName(null, "domain\\userName")).thenReturn(null);

        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper(win32PlatformWrapper);

        assertThat(authenticationHelper.getUserDetails("domain\\userName")).isNull();
        Mockito.verify(win32PlatformWrapper, Mockito.never()).getUserGroups("domain", "userName");
        Mockito.verify(win32PlatformWrapper, Mockito.times(1)).getAccountByName(null, "domain\\userName");
    }

    private static void runLogonUserTest(final String domainName, final String userDomainNameSeparator,
                                         final String userName, final String password, boolean isUserNameFormatValid,
                                         boolean isUserValid, boolean expectedIsUserAuthenticated) {
        // Parameters consistency check
        assertThat(!isUserNameFormatValid && isUserValid).isFalse();

        String userNameWithDomain = getUserNameWithDomain(domainName, userDomainNameSeparator, userName);
        int expectedInvocationCountGetAccountByName = 0;
        int expectedInvocationCountLogonUser = 0;
        Advapi32Util.Account account = null;
        if (isUserNameFormatValid && isUserValid) {
            account = new Advapi32Util.Account();
            account.domain = domainName;
            account.name = userName;
            account.fqn = userNameWithDomain;
        }

        if (isUserNameFormatValid) {
            expectedInvocationCountGetAccountByName = 1;
        }
        if (isUserValid) {
            expectedInvocationCountLogonUser = 1;
        }

        Win32PlatformWrapper win32PlatformWrapper = Mockito.mock(Win32PlatformWrapper.class);
        Mockito.when(win32PlatformWrapper.logonUser(userName, domainName, password, WinBase.LOGON32_LOGON_NETWORK,
                WinBase.LOGON32_PROVIDER_DEFAULT)).thenReturn(expectedIsUserAuthenticated);
        Mockito.when(win32PlatformWrapper.getAccountByName(null, userNameWithDomain)).thenReturn(account);
        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper(win32PlatformWrapper);

        assertThat(authenticationHelper.logonUser(getUserNameWithDomain(domainName, userDomainNameSeparator, userName),
                password)).isEqualTo(expectedIsUserAuthenticated);


        Mockito.verify(win32PlatformWrapper, Mockito.times(expectedInvocationCountLogonUser)).
                logonUser(userName, domainName, password, WinBase.LOGON32_LOGON_NETWORK, WinBase.LOGON32_PROVIDER_DEFAULT);
        Mockito.verify(win32PlatformWrapper, Mockito.times(expectedInvocationCountGetAccountByName)).
                getAccountByName(null, userNameWithDomain);
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

    private static Collection<String> getUserGroups(DomainGroup[] domainGroups) {
        Collection<String> userGroups = new ArrayList<String>();
        if (domainGroups != null) {
            for (DomainGroup domainGroup : domainGroups) {
                String group = domainGroup.getDomainName() + "\\" + domainGroup.getGroupName();
                userGroups.add(group.toLowerCase());
            }
        }
        return userGroups;
    }

    private static void runGetGroupsTest(final String domainName, final String separator, final String userAlias,
                                         boolean isUserNameFormatValid, boolean isUserValid,
                                         DomainGroup[] domainGroups) {
        // Parameters consistency check
        assertThat(!isUserNameFormatValid && isUserValid).isFalse();

        int expectedInvocationCountGetAccountByName = 0;
        int expectedInvocationCountGetGroups = 0;
        if (isUserNameFormatValid) {
            expectedInvocationCountGetAccountByName = 1;
        }
        if (isUserValid) {
            expectedInvocationCountGetGroups = 1;
        }

        Collection<String> expectedUserGroups = getUserGroups(domainGroups);
        String userNameWithDomain = getUserNameWithDomain(domainName, separator, userAlias);
        Advapi32Util.Account account = null;
        if (isUserNameFormatValid && isUserValid) {
            account = new Advapi32Util.Account();
            account.domain = domainName;
            account.name = userAlias;
            account.fqn = userNameWithDomain;
        }

        Win32PlatformWrapper win32PlatformWrapper = Mockito.mock(Win32PlatformWrapper.class);
        Mockito.when(win32PlatformWrapper.getUserGroups(userAlias, domainName)).
                thenReturn(getNetApi32UtilGroups(domainGroups));
        Mockito.when(win32PlatformWrapper.getAccountByName(null, userNameWithDomain)).thenReturn(account);

        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper(win32PlatformWrapper);
        Collection<String> actualUserGroups = authenticationHelper.getGroups(userNameWithDomain);

        assertThat(CollectionUtils.isEqualCollection(actualUserGroups, expectedUserGroups)).isTrue();
        Mockito.verify(win32PlatformWrapper, Mockito.times(expectedInvocationCountGetAccountByName)).
                getAccountByName(null, userNameWithDomain);
        Mockito.verify(win32PlatformWrapper, Mockito.times(expectedInvocationCountGetGroups)).
                getUserGroups(userAlias, domainName);
    }

    private static Netapi32Util.Group[] getNetApi32UtilGroups(DomainGroup[] domainGroups) {
        if (domainGroups != null) {
            Netapi32Util.Group[] groups = new Netapi32Util.Group[domainGroups.length];
            for (int i = 0; i < domainGroups.length; i++) {
                Netapi32Util.Group netapi32UtilGroup = new Netapi32Util.Group();
                netapi32UtilGroup.name = domainGroups[i].getGroupName();

                groups[i] = netapi32UtilGroup;
            }
            return groups;
        }

        return null;
    }

    private static void runGetUserDetailsForValidUserNameTest(String userName, String expectedFqn) {
        Advapi32Util.Account account = null;
        if (expectedFqn != null && !expectedFqn.isEmpty()) {
            account = new Advapi32Util.Account();
            account.fqn = expectedFqn;
        }

        Win32PlatformWrapper win32PlatformWrapper = Mockito.mock(Win32PlatformWrapper.class);
        Mockito.when(win32PlatformWrapper.getAccountByName(null, userName)).thenReturn(account);

        WindowsAuthenticationHelper authenticationHelper = new WindowsAuthenticationHelper(win32PlatformWrapper);

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

    class DomainGroup {
        private String domainName;
        private String groupName;

        public String getDomainName() {
            return domainName;
        }

        public void setDomainName(String domainName) {
            this.domainName = domainName;
        }

        public String getGroupName() {
            return groupName;
        }

        public void setGroupName(String groupName) {
            this.groupName = groupName;
        }
    }
}
