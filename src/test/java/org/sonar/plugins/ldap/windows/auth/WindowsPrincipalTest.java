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

import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.WinNT;
import org.apache.commons.lang.NullArgumentException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsPrincipalTest {
    private IWin32PlatformWrapper win32PlatformWrapper;
    private WinNT.HANDLE pUserHandle;

    @Before
    public void init() {
        pUserHandle = Mockito.mock(WinNT.HANDLE.class);
        win32PlatformWrapper = Mockito.mock(IWin32PlatformWrapper.class);
    }

    @Test(expected = NullArgumentException.class)
    public void nullArgumentCheckOnConstructor() {
        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(null);
    }

    @Test(expected = NullArgumentException.class)
    public void nullArgumentCheckOnWin32PlatformWrapper() {
        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(pUserHandle, null);
    }

    @Test
    public void getFqnTest() {
        Advapi32Util.Account account = getTestAdvapi32UtilAccount();
        Mockito.when(win32PlatformWrapper.getTokenAccount(pUserHandle)).thenReturn(account);

        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(pUserHandle, win32PlatformWrapper);

        assertThat(windowsPrincipal.getFqn()).isEqualTo(account.fqn);
    }

    @Test
    public void getNameTest() {
        Advapi32Util.Account account = getTestAdvapi32UtilAccount();
        Mockito.when(win32PlatformWrapper.getTokenAccount(pUserHandle)).thenReturn(account);

        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(pUserHandle, win32PlatformWrapper);

        assertThat(windowsPrincipal.getName()).isEqualTo(account.fqn);
    }

    @Test
    public void getGroupsWhenGetTokenGroupsReturnsNull() {
        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(pUserHandle, win32PlatformWrapper);
        assertThat(windowsPrincipal.getGroups()).isNull();
    }

    @Test
    public void getGroupsWhenGetTokenGroupsReturnsEmpty() {
        Mockito.when(win32PlatformWrapper.getTokenGroups(pUserHandle)).thenReturn(new Advapi32Util.Account[0]);
        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(pUserHandle, win32PlatformWrapper);

        assertThat(windowsPrincipal.getGroups()).isEmpty();
    }

    @Test
    public void getGroupsNormalTests() {
        Advapi32Util.Account[] accounts = getTestAdvapi32UtilAccounts();
        Mockito.when(win32PlatformWrapper.getTokenGroups(pUserHandle)).thenReturn(accounts);
        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(pUserHandle, win32PlatformWrapper);

        assertThat(windowsPrincipal.getGroups()).isEqualTo(getWindowsAccounts(accounts));
    }

    @Test
    public void equalsTest() {
        Advapi32Util.Account account = getTestAdvapi32UtilAccount();
        Mockito.when(win32PlatformWrapper.getTokenAccount(pUserHandle)).thenReturn(account);
        WindowsPrincipal otherWindowsPrincipalEqual = new WindowsPrincipal(pUserHandle, win32PlatformWrapper);
        WindowsPrincipal otherWindowsPrincipalNotEqual = new WindowsPrincipal(new WinNT.HANDLE(), win32PlatformWrapper);

        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(pUserHandle, win32PlatformWrapper);

        assertThat(windowsPrincipal.equals(windowsPrincipal)).isTrue();
        assertThat(windowsPrincipal.equals(null)).isFalse();
        assertThat(windowsPrincipal.equals(new Object())).isFalse();
        assertThat(windowsPrincipal.equals(otherWindowsPrincipalNotEqual)).isFalse();
        assertThat(windowsPrincipal.equals(otherWindowsPrincipalEqual)).isTrue();
    }

    @Test
    public void hashCodeTest() {
        Advapi32Util.Account account = getTestAdvapi32UtilAccount();
        Mockito.when(win32PlatformWrapper.getTokenAccount(pUserHandle)).thenReturn(account);
        WindowsPrincipal windowsPrincipal = new WindowsPrincipal(pUserHandle, win32PlatformWrapper);

        assertThat(windowsPrincipal.hashCode()).isEqualTo(windowsPrincipal.getFqn().hashCode());
    }

    private static Advapi32Util.Account getTestAdvapi32UtilAccount() {
        return getTestAdvapi32UtilAccount("domain", "user", "account-sid", "domain\\user");
    }

    private static Advapi32Util.Account getTestAdvapi32UtilAccount(String domain, String user, String sidString,
                                                                   String fqn) {
        Advapi32Util.Account account = new Advapi32Util.Account();
        account.domain = fqn;
        account.name = user;
        account.sidString = sidString;
        account.fqn = fqn;

        return account;
    }

    private static Advapi32Util.Account[] getTestAdvapi32UtilAccounts() {
        Advapi32Util.Account[] accounts = new Advapi32Util.Account[2];
        accounts[0] = getTestAdvapi32UtilAccount("domain", "user1", "account-sid1", "domain\\user1");
        accounts[1] = getTestAdvapi32UtilAccount("domain", "user2", "account-sid2", "domain\\user2");

        return accounts;
    }

    private static WindowsAccount[] getWindowsAccounts(Advapi32Util.Account[] accounts) {
        WindowsAccount[] windowsAccounts = new WindowsAccount[accounts.length];
        for (int i = 0; i < accounts.length; i++) {
            windowsAccounts[i] = new WindowsAccount(accounts[i]);
        }

        return windowsAccounts;
    }
}
