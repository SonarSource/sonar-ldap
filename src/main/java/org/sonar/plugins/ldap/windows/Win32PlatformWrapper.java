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

import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Netapi32Util;
import com.sun.jna.platform.win32.WinNT;

/**
 * Wrapper class over Win32 APIs
 */
public class Win32PlatformWrapper {
    public boolean logonUser(final String username, final String domain, final String password,
                             final int logonType, final int logonProvider, WinNT.HANDLEByReference pHandleUser) {
        return Advapi32.INSTANCE.LogonUser(username, domain, password, logonType, logonProvider, pHandleUser);
    }

    public boolean logonUser(final String username, final String domain, final String password,
                             final int logonType, final int logonProvider) {
        WinNT.HANDLEByReference pHandleUser = new WinNT.HANDLEByReference();
        return logonUser(username, domain, password, logonType, logonProvider, pHandleUser);
    }

    public Advapi32Util.Account getAccountByName(final String systemName, final String userName) {
        return Advapi32Util.getAccountByName(systemName, userName);
    }

    public Netapi32Util.Group[] getUserGroups(final String userAlias, final String domainName) {
        return Netapi32Util.getUserGroups(userAlias, domainName);
    }
}
