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

/* A Serializable Windows Account */
public class WindowsAccount implements Serializable {
    /* SerialVersionUID */
    private static final long serialVersionUID = 1L;

    private final String sidString;
    private final String name;
    private final String domain;
    private final String fqn;

    public WindowsAccount(final Advapi32Util.Account account) {
        if (account == null) {
            throw new NullArgumentException("account");
        }
        sidString = account.sidString;
        name = account.name;
        domain = account.domain;
        fqn = account.fqn;
    }

    /**
     * Gets the account name.
     *
     * @return {@link String}
     */
    public String getName() {
        return name;
    }

    /**
     * Gets the account's domain.
     *
     * @return {@link String}
     */
    public String getDomainName() {
        return domain;
    }

    /**
     * Gets the fqn.
     *
     * @return {@link String}
     */
    public String getFqn() {
        return fqn;
    }

    /**
     * Gets Sid string
     *
     * @return {@link String}
     */
    public String getSidString() {
        return sidString;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object o) {

        if (o == this) {
            return true;
        }

        if (o instanceof WindowsAccount) {
            return getSidString().equals(((WindowsAccount) o).getSidString());
        }

        return false;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return getSidString().hashCode();
    }
}
