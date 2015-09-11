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

/**
 * A Win32 platform APIs wrapper
 */
public interface IWin32PlatformWrapper {
    boolean logonUser(final String username, final String domain, final String password,
                      final int logonType, final int logonProvider, WinNT.HANDLEByReference pHandleUser);

    Advapi32Util.Account getAccountByName(final String systemName, final String userName);

    Advapi32Util.Account getTokenAccount(final WinNT.HANDLE windowsIdentity);

    Advapi32Util.Account[] getTokenGroups(final WinNT.HANDLE windowsIdentity);

    String getLastErrorMessage();

    void closeHandle(final WinNT.HANDLE identityHandle);
}
