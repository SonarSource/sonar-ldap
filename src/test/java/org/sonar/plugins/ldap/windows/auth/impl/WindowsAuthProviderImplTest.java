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
package org.sonar.plugins.ldap.windows.auth.impl;

import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.sonar.plugins.ldap.windows.auth.IWin32PlatformWrapper;
import org.sonar.plugins.ldap.windows.auth.IWindowsAuthProvider;
import org.sonar.plugins.ldap.windows.auth.WindowsAccount;
import org.sonar.plugins.ldap.windows.auth.WindowsPrincipal;

import static org.assertj.core.api.Assertions.assertThat;


public class WindowsAuthProviderImplTest {
    private WindowsAuthProviderImpl windowsAuthProvider;
    private IWin32PlatformWrapper win32PlatformWrapper;

    @Before
    public void init() {
        win32PlatformWrapper = Mockito.mock(IWin32PlatformWrapper.class);
        windowsAuthProvider = new WindowsAuthProviderImpl(win32PlatformWrapper);
    }

    @Test
    public void windowsAuthProviderImplInterfaceImplementationTests() {
        assertThat(windowsAuthProvider).isInstanceOf(IWindowsAuthProvider.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void logonDomainUserDomainNameArgumentNull() {
        windowsAuthProvider.logonDomainUser(null, "user", "secret");
    }

    @Test(expected = IllegalArgumentException.class)
    public void logonDomainUserDomainNameArgumentEmpty() {
        windowsAuthProvider.logonDomainUser("", "user", "secret");
    }

    @Test(expected = IllegalArgumentException.class)
    public void logonDomainUserNameArgumentNull() {
        windowsAuthProvider.logonDomainUser("domain", null, "secret");
    }

    @Test(expected = IllegalArgumentException.class)
    public void logonDomainUserNameArgumentEmpty() {
        windowsAuthProvider.logonDomainUser("domain", "", "secret");
    }

    @Test(expected = IllegalArgumentException.class)
    public void logonDomainUserPasswordArgumentNull() {
        windowsAuthProvider.logonDomainUser("domain", "user", null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void logonDomainUserPasswordArgumentEmpty() {
        windowsAuthProvider.logonDomainUser("domain", "user", "");
    }

    @Test
    public void logonDomainUserTest() {
        WinNT.HANDLE pUserHandle = new WinNT.HANDLE(new Pointer(1000));
        runLogonDomainUserTest("domain", "user", "secret", pUserHandle);
        runLogonDomainUserTest("domain", "user", "invalid-secret", null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void lookupAccountArgumentNull() {
        windowsAuthProvider.lookupAccount(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void lookupAccountArgumentEmpty() {
        windowsAuthProvider.lookupAccount("");
    }

    @Test
    public void lookupAccountInvalidUserNames() {
        runLookupAccountTest(null, "\\", "", false, null);
        runLookupAccountTest(null, "\\", null, false, null);
        runLookupAccountTest("", "\\", null, false, null);
        runLookupAccountTest("", "\\", "", false, null);
        runLookupAccountTest("user", "@", "domain", false, null);
        runLookupAccountTest("user@domain", "", "", false, null);
        runLookupAccountTest("domain", "\\", "user\\other-format", false, null);
    }

    @Test
    public void lookupAccountValidUserNames() {
        WindowsAccount windowsAccount = new WindowsAccount(getAdvapi32UtilAccount("domain", "\\", "user"));
        runLookupAccountTest("domain", "\\", "user", true, windowsAccount);
        runLookupAccountTest("domain", "\\", "user", true, null);
    }

    @Test
    public void getUserDetailsWhenGetAccountByNameThrowsExceptionTest() {
        IWin32PlatformWrapper win32PlatformWrapper = Mockito.mock(IWin32PlatformWrapper.class);
        Win32Exception win32Exception = Mockito.mock(Win32Exception.class);
        Mockito.when(win32Exception.getMessage()).thenReturn("Win32Exception occurred");
        Mockito.when(win32PlatformWrapper.getAccountByName(null, "domain\\userName")).thenThrow(win32Exception);

        IWindowsAuthProvider windowsAuthProvider = new WindowsAuthProviderImpl(win32PlatformWrapper);

        assertThat(windowsAuthProvider.lookupAccount("domain\\userName")).isNull();

        Mockito.verify(win32Exception, Mockito.times(1)).getMessage();
        Mockito.verify(win32PlatformWrapper, Mockito.times(1)).getAccountByName(null, "domain\\userName");
    }

    private static void runLogonDomainUserTest(final String domainName, final String userName, final String password,
                                               final WinNT.HANDLE expectedUserHandle) {
        Advapi32Util.Account account = new Advapi32Util.Account();
        account.fqn = getUserNameWithDomain(domainName, "\\", userName);
        IWin32PlatformWrapper win32PlatformWrapper = Mockito.mock(IWin32PlatformWrapper.class);
        Mockito.when(win32PlatformWrapper.getTokenAccount(expectedUserHandle)).thenReturn(account);

        WindowsPrincipal exWindowPrincipal = null;
        if (expectedUserHandle != null) {
            exWindowPrincipal = new WindowsPrincipal(expectedUserHandle, win32PlatformWrapper);
        }
        final WindowsPrincipal expectedWindowsPrincipal = exWindowPrincipal;

        Mockito.when(win32PlatformWrapper.logonUser(Mockito.anyString(), Mockito.anyString(), Mockito.anyString(),
                Mockito.anyInt(), Mockito.anyInt(),
                Mockito.any(WinNT.HANDLEByReference.class))).thenAnswer(new Answer<Boolean>() {
            public Boolean answer(InvocationOnMock invocation)
                    throws Throwable {
                Object[] args = invocation.getArguments();
                String uName = (String) args[0];
                String dName = (String) args[1];
                String pwd = (String) args[2];
                int lType = (int) args[3];
                int lProvider = (int) args[4];
                WinNT.HANDLEByReference handleByRef = (WinNT.HANDLEByReference) args[5];

                boolean isUserAuthenticated = uName.equals(userName) && dName.equals(domainName) && pwd.equals(password)
                        && lType == WinBase.LOGON32_LOGON_NETWORK && lProvider == WinBase.LOGON32_PROVIDER_DEFAULT
                        && expectedWindowsPrincipal != null;
                if (isUserAuthenticated) {
                    handleByRef.setValue(expectedUserHandle);
                }
                return isUserAuthenticated;
            }
        });
        WindowsAuthProviderImpl windowsAuthProvider = new WindowsAuthProviderImpl(win32PlatformWrapper);

        WindowsPrincipal windowsPrincipal = windowsAuthProvider.logonDomainUser(domainName, userName, password);

        if (expectedWindowsPrincipal == null) {
            assertThat(windowsPrincipal).isNull();
            Mockito.verify(win32PlatformWrapper, Mockito.times(1)).getLastErrorMessage();
        } else {
            assertThat(windowsPrincipal).isEqualTo(expectedWindowsPrincipal);
            Mockito.verify(win32PlatformWrapper, Mockito.times(0)).getLastErrorMessage();
            Mockito.verify(win32PlatformWrapper, Mockito.times(1)).closeHandle(expectedUserHandle);
        }
    }

    private static void runLookupAccountTest(final String domainName, final String userDomainNameSeparator,
                                             final String userName, boolean isUserNameFormatValid,
                                             WindowsAccount expectedWindowsAccount) {
        String userNameWithDomain = getUserNameWithDomain(domainName, userDomainNameSeparator, userName);
        int expectedInvocationCountGetAccountByName = 0;

        if (isUserNameFormatValid) {
            expectedInvocationCountGetAccountByName = 1;
        }

        Advapi32Util.Account account = null;
        if (isUserNameFormatValid) {
            account = getAdvapi32UtilAccount(domainName, userDomainNameSeparator, userName);
        }

        IWin32PlatformWrapper win32PlatformWrapper = Mockito.mock(IWin32PlatformWrapper.class);
        if (expectedWindowsAccount != null) {
            Mockito.when(win32PlatformWrapper.getAccountByName(null, userNameWithDomain)).thenReturn(account);
        }

        IWindowsAuthProvider windowsAuthProvider = new WindowsAuthProviderImpl(win32PlatformWrapper);

        WindowsAccount windowsAccount = windowsAuthProvider.lookupAccount(userNameWithDomain);

        if (expectedWindowsAccount == null) {
            assertThat(windowsAccount).isNull();
        } else {
            assertThat(windowsAccount.getSidString()).isEqualTo(expectedWindowsAccount.getSidString());
            assertThat(windowsAccount.getDomainName()).isEqualTo(expectedWindowsAccount.getDomainName());
            assertThat(windowsAccount.getFqn()).isEqualTo(expectedWindowsAccount.getFqn());
            assertThat(windowsAccount.getName()).isEqualTo(expectedWindowsAccount.getName());
        }

        Mockito.verify(win32PlatformWrapper, Mockito.times(expectedInvocationCountGetAccountByName)).
                getAccountByName(null, userNameWithDomain);

    }

    private static Advapi32Util.Account getAdvapi32UtilAccount(final String domainName, final String separator,
                                                               final String userName) {
        String userNameWithDomain = getUserNameWithDomain(domainName, separator, userName);
        Advapi32Util.Account account = new Advapi32Util.Account();
        account.domain = domainName;
        account.sidString = "Sid-" + userNameWithDomain;
        account.name = userName;
        account.fqn = userNameWithDomain;

        return account;
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
