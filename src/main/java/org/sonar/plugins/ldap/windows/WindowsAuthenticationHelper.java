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

import org.sonar.api.ServerExtension;
import org.sonar.api.security.UserDetails;
import org.sonar.plugins.ldap.windows.auth.IWindowsAuthProvider;
import org.sonar.plugins.ldap.windows.auth.WindowsAccount;
import org.sonar.plugins.ldap.windows.auth.WindowsPrincipal;
import org.sonar.plugins.ldap.windows.auth.impl.WindowsAuthProviderImpl;

public class WindowsAuthenticationHelper implements ServerExtension {
    public static final String WINDOWS_PRINCIPAL = "windows_principal";
    public static final String USER_GROUPS_SYNCHRONIZED = "user_group_synchronized";

    private final IWindowsAuthProvider windowsAuthProvider;

    public WindowsAuthenticationHelper() {
        this(new WindowsAuthProviderImpl());
    }

    WindowsAuthenticationHelper(IWindowsAuthProvider windowsAuthProvider) {
        this.windowsAuthProvider = windowsAuthProvider;
    }

    /**
     * Authenticates the user using the provided username and password
     *
     * @param userName Username of the user. Should be in domain\\user format
     * @param password Password of the user
     * @return Returns {@link WindowsPrincipal} if user is authenticated successfully, otherwise returns null.
     */
    public WindowsPrincipal logonUser(final String userName, final String password) {
        if (userName == null || userName.isEmpty()) {
            throw new IllegalArgumentException("username is null or empty");
        }

        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("password is null or empty");
        }

        WindowsPrincipal windowsPrincipal = null;
        WindowsAccount windowsAccount = windowsAuthProvider.lookupAccount(userName);
        if (windowsAccount != null) {
            windowsPrincipal = windowsAuthProvider.logonDomainUser(windowsAccount.getDomainName(),
                    windowsAccount.getName(), password);
        }

        return windowsPrincipal;
    }

    /**
     * Gets the {@link UserDetails} for the given domain user.
     *
     * @param userName The user name of the user. Should be in domain\\user format
     * @return {@link UserDetails} for the given domain user or null if the domain user is not found
     */
    public UserDetails getUserDetails(final String userName) {
        if (userName == null || userName.isEmpty()) {
            throw new IllegalArgumentException("userName is null or empty.");
        }
        UserDetails userDetails = null;

        WindowsAccount windowsAccount = windowsAuthProvider.lookupAccount(userName);
        if (windowsAccount != null) {
            userDetails = new UserDetails();
            // Setting the name to User's Fully qualified Name
            userDetails.setName(windowsAccount.getFqn());
            // Not getting Email for the user
        }

        return userDetails;
    }
}
