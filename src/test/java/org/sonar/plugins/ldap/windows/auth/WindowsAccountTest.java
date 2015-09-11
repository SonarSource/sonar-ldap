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
import java.io.Serializable;
import org.apache.commons.lang.NullArgumentException;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsAccountTest {
    private Advapi32Util.Account account;
    private WindowsAccount windowsAccount;

    @Before
    public void init() {
        account = getTestAccount();
        windowsAccount = new WindowsAccount(account);
    }

    @Test(expected = NullArgumentException.class)
    public void nullArgumentCheckOnConstructor() {
        WindowsAccount windowsAccount = new WindowsAccount(null);
    }

    @Test
    public void windowsAccountInterfaceImplementationTests() {
        ;
        assertThat(windowsAccount).isInstanceOf(Serializable.class);
    }

    @Test
    public void windowsAccountConstructorTest() {
        assertThat(windowsAccount.getSidString()).isEqualTo(account.sidString);
        assertThat(windowsAccount.getName()).isEqualTo(account.name);
        assertThat(windowsAccount.getDomainName()).isEqualTo(account.domain);
        assertThat(windowsAccount.getFqn()).isEqualTo(account.fqn);
    }

    @Test
    public void equalsTest() {
        WindowsAccount otherWindowsAccountEqual = new WindowsAccount(account);
        WindowsAccount otherWindowsAccountNotEqual = new WindowsAccount(new Advapi32Util.Account());

        assertThat(windowsAccount.equals(windowsAccount)).isTrue();
        assertThat(windowsAccount.equals(null)).isFalse();
        assertThat(windowsAccount.equals(new Object())).isFalse();
        assertThat(windowsAccount.equals(otherWindowsAccountNotEqual)).isFalse();
        assertThat(windowsAccount.equals(otherWindowsAccountEqual)).isTrue();
    }

    @Test
    public void hashCodeTest() {
        assertThat(windowsAccount.hashCode()).isEqualTo(windowsAccount.getSidString().hashCode());
    }

    private Advapi32Util.Account getTestAccount() {
        Advapi32Util.Account account = new Advapi32Util.Account();
        account.sidString = "Account-SID";
        account.name = "Account-Name";
        account.domain = "Account-DomainName";
        account.fqn = "Account-fqn";

        return account;
    }
}
