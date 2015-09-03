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

/**
 * A Windows Authentication Provider
 */
public interface IWindowsAuthProvider {
    /**
     * Tries to login a user to the local computer using a network logon and the default authentication provider
     *
     * @param domain   Domain of the user.
     * @param userName Username of the user.
     * @param password Password of the user
     * @return Returns {@link WindowsPrincipal} if user is authenticated successfully, otherwise returns null.
     */
    WindowsPrincipal logonDomainUser(final String domain, final String userName, final String password);

    /**
     * Looks-up the windows account for the given domain user.
     *
     * @param userName userName of the user. Should be in domain\\user format.
     * @return {@link WindowsAccount}
     */
    WindowsAccount lookupAccount(final String userName);
}
