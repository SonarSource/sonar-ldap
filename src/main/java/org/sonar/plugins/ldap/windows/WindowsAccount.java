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

/**
 * Windows account
 */
public class WindowsAccount {
    private final Advapi32Util.Account account;

    public WindowsAccount(final Advapi32Util.Account account) {
        if (account == null) {
            throw new NullArgumentException("account");
        }
        this.account = account;
    }

    /**
     * Account's domain-name
     *
     * @return {@link String}
     */
    public String getDomainName() {
        return account.domain;
    }

    /**
     * Account's user name
     *
     * @return {@link String}
     */
    public String getUserName() {
        return account.name;
    }

    /**
     * Account's fully qualified name
     *
     * @return {@link String}
     */
    public String getFqn() {
        return account.fqn;
    }
}
