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

import com.sun.jna.platform.win32.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.security.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WindowsAuthenticationHelper {
    private static final Logger LOG = LoggerFactory.getLogger(WindowsAuthenticationHelper.class);
    private Win32PlatformWrapper win32PlatformWrapper;

    public WindowsAuthenticationHelper() {
        this(new Win32PlatformWrapper());
    }

    WindowsAuthenticationHelper(Win32PlatformWrapper win32PlatformWrapper) {
        this.win32PlatformWrapper = win32PlatformWrapper;
    }

    /**
     * Authenticates the user using the provided username and password
     *
     * @param userName Username of the user. Should be in domain\\user format
     * @param password Password of the user
     * @return Returns true if user is authenticated successfully, otherwise returns false.
     */
    public boolean logonUser(final String userName, final String password) {
        if (userName == null || userName.isEmpty()) {
            throw new IllegalArgumentException("username is null or empty");
        }

        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("password is null or empty");
        }

        boolean isUserAuthenticated = false;

        WindowsAccount windowsAccount = lookupAccount(userName);
        if (windowsAccount != null) {
            // Logon to the local machine using the default logon provider: Negotiate and NTLM
            isUserAuthenticated = win32PlatformWrapper.logonUser(windowsAccount.getUserName(),
                    windowsAccount.getDomainName(), password, WinBase.LOGON32_LOGON_NETWORK,
                    WinBase.LOGON32_PROVIDER_DEFAULT);
            if (!isUserAuthenticated) {
                LOG.debug("User {} is not authenticated : {}", userName, win32PlatformWrapper.getLastErrorMessage());
            }
        }

        return isUserAuthenticated;
    }

    /**
     * Fetches the group information for the given domain user. Note that it doesn't fetch the groups information
     * across domains in the forest.
     *
     * @param userName The username of the user. Should be in domain\\user format.
     * @return {@link Collection} of domain groups of which the user is part of.
     */
    public Collection<String> getGroups(final String userName) {
        if (userName == null || userName.isEmpty()) {
            throw new IllegalArgumentException("userName should not be null or empty");
        }
        Collection<String> groups = new ArrayList<String>();

        WindowsAccount windowsAccount = lookupAccount(userName);
        if (windowsAccount != null) {
            Netapi32Util.Group[] userGroups = win32PlatformWrapper.getUserGroups(windowsAccount.getUserName(), windowsAccount.getDomainName());
            if (userGroups != null) {
                for (int i = 0; i < userGroups.length; i++) {
                    String group = windowsAccount.getDomainName() + "\\" + userGroups[i].name;
                    groups.add(group.toLowerCase());
                }
            }
        }

        return groups;
    }

    /**
     * Gets the {@link UserDetails} for the given domain user.
     *
     * @param userName The user name of the user. Should be in domain\\user format
     * @return {@link UserDetails} for the given domain user
     */
    public UserDetails getUserDetails(final String userName) {
        if (userName == null || userName.isEmpty()) {
            throw new IllegalArgumentException("userName is null or empty.");
        }

        UserDetails userDetails = null;

        WindowsAccount windowsAccount = lookupAccount(userName);
        if (windowsAccount != null) {
            userDetails = new UserDetails();
            // Setting the name to User's Fully qualified Name
            userDetails.setName(windowsAccount.getFqn());
            // Not getting Email for the user
        }

        return userDetails;
    }

    private WindowsAccount lookupAccount(final String userName) {
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
