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
import org.apache.commons.lang.NullArgumentException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WindowsAccountTest {

    @Test(expected = NullArgumentException.class)
    public void nullArgumentCheckOnConstructor() {
        WindowsAccount windowsAccount = new WindowsAccount(null);
    }

    public void windowsAccountConstructorTest() {
        Advapi32Util.Account account = new Advapi32Util.Account();
        account.name = "name";
        account.domain = "domain";
        account.fqn = "domain\\name";

        WindowsAccount windowsAccount = new WindowsAccount(account);
        assertThat(windowsAccount.getUserName()).isEqualTo(account.name);
        assertThat(windowsAccount.getDomainName()).isEqualTo(account.domain);
        assertThat(windowsAccount.getFqn()).isEqualTo(account.fqn);
    }
}
