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

import com.google.common.base.Preconditions;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.ldap.windows.auth.IWin32PlatformWrapper;
import org.sonar.plugins.ldap.windows.auth.IWindowsAuthProvider;
import org.sonar.plugins.ldap.windows.auth.WindowsAccount;
import org.sonar.plugins.ldap.windows.auth.WindowsPrincipal;

public class WindowsAuthProviderImpl implements IWindowsAuthProvider {
    private static final Logger LOG = LoggerFactory.getLogger(WindowsAuthProviderImpl.class);
    private final IWin32PlatformWrapper win32PlatformWrapper;

    public WindowsAuthProviderImpl() {
        this(new Win32PlatformWrapperImpl());
    }

    WindowsAuthProviderImpl(IWin32PlatformWrapper win32PlatformWrapper) {
        this.win32PlatformWrapper = win32PlatformWrapper;
    }

    /* (non-Javadoc)
     * @see IWindowsAuthProvider#logonDomainUser()
     */
    @Override
    public WindowsPrincipal logonDomainUser(final String domain, final String userName, final String password) {
        Preconditions.checkArgument(domain != null && !domain.isEmpty(), "domain is null or empty");
        Preconditions.checkArgument(userName != null && !userName.isEmpty(), "userName is null or empty");
        Preconditions.checkArgument(password != null && !password.isEmpty(), "password is null or empty");

        final WinNT.HANDLEByReference pHandleUser = new WinNT.HANDLEByReference();
        WindowsPrincipal windowsPrincipal = null;
        if (!win32PlatformWrapper.logonUser(userName, domain, password, WinBase.LOGON32_LOGON_NETWORK,
                WinBase.LOGON32_PROVIDER_DEFAULT, pHandleUser)) {
            LOG.debug("User {} is not authenticated : {}", domain + "\\" + userName,
                    win32PlatformWrapper.getLastErrorMessage());
        } else {
            WinNT.HANDLE identityHandle = pHandleUser.getValue();
            try {
                windowsPrincipal = new WindowsPrincipal(pHandleUser.getValue(), win32PlatformWrapper);
            } finally {
                win32PlatformWrapper.closeHandle(identityHandle);
            }
        }

        return windowsPrincipal;
    }

    /* (non-Javadoc)
     * @see IWindowsAuthProvider#lookupAccount()
     */
    @Override
    public WindowsAccount lookupAccount(final String userName) {
        Preconditions.checkArgument(userName != null && !userName.isEmpty(), "userName is null or empty");

        WindowsAccount windowsAccount = null;
        if (isValidUserNamePattern(userName)) {
            try {
                Advapi32Util.Account account = win32PlatformWrapper.getAccountByName(null, userName);
                if (account != null) {
                    windowsAccount = new WindowsAccount(account);
                } else {
                    LOG.debug("User {} is not found.", userName);
                }
            } catch (Win32Exception e) {
                LOG.debug("User {} is not found: {}", userName, e.getMessage());
            }
        } else {
            LOG.debug("Invalid user-name format for the user: {}. Expected format: domain\\user.", userName);
        }

        return windowsAccount;
    }

    private boolean isValidUserNamePattern(final String userName) {
        Pattern userNamePattern = Pattern.compile("(\\w+)\\\\(\\w+)");
        Matcher parts = userNamePattern.matcher(userName);
        return parts.matches();
    }
}
