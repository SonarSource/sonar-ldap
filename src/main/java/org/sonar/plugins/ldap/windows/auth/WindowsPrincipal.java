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
import java.io.Serializable;
import java.security.Principal;
import org.apache.commons.lang.NullArgumentException;
import org.sonar.plugins.ldap.windows.auth.impl.Win32PlatformWrapperImpl;

public class WindowsPrincipal implements Principal, Serializable {

    /* SerialVersionUID. */
    private static final long serialVersionUID = 1L;

    private final String fqn;
    private final WindowsAccount[] userGroups;

    public WindowsPrincipal(final WinNT.HANDLE windowsIdentity) {
        this(windowsIdentity, new Win32PlatformWrapperImpl());
    }

    public WindowsPrincipal(final WinNT.HANDLE pUserHandle, IWin32PlatformWrapper win32PlatformWrapper) {
        if (pUserHandle == null) {
            throw new NullArgumentException("pUserHandle");
        }

        if (win32PlatformWrapper == null) {
            throw new NullArgumentException("win32PlatformWrapper");
        }

        fqn = getUserFqn(pUserHandle, win32PlatformWrapper);
        userGroups = WindowsPrincipal.getUserGroups(pUserHandle, win32PlatformWrapper);
    }


    /**
     * Fully qualified name.
     *
     * @return {@link String}
     */
    public String getFqn() {
        return fqn;
    }

    /**
     * Returns collection of user groups
     *
     * @return An array of {@link WindowsAccount}
     */
    public WindowsAccount[] getGroups() {
        return userGroups;
    }

    @Override
    public String getName() {
        return fqn;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object o) {

        if (o == this) {
            return true;
        }

        if (o instanceof WindowsPrincipal) {
            return getFqn().equals(((WindowsPrincipal) o).getFqn());
        }

        return false;
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return getFqn().hashCode();
    }

    private static WindowsAccount[] getUserGroups(final WinNT.HANDLE pUserHandle, IWin32PlatformWrapper win32PlatformWrapper) {
        WindowsAccount[] userGroups = null;
        Advapi32Util.Account[] groups = win32PlatformWrapper.getTokenGroups(pUserHandle);
        if (groups != null) {
            userGroups = new WindowsAccount[groups.length];
            for (int i = 0; i < groups.length; i++) {
                userGroups[i] = new WindowsAccount(groups[i]);
            }
        }

        return userGroups;

    }

    private static String getUserFqn(final WinNT.HANDLE pUserHandle, IWin32PlatformWrapper win32PlatformWrapper) {
        Advapi32Util.Account account = win32PlatformWrapper.getTokenAccount(pUserHandle);
        return account != null ? account.fqn : null;
    }
}
