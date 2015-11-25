/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009 SonarSource
 * sonarqube@googlegroups.com
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

import com.sun.jna.platform.win32.Win32Exception;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import javax.annotation.CheckForNull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.sonar.api.security.UserDetails;
import org.sonar.api.server.ServerSide;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import waffle.servlet.NegotiateSecurityFilter;
import waffle.servlet.WindowsPrincipal;
import waffle.windows.auth.IWindowsAccount;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.WindowsAccount;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static org.apache.commons.lang.StringUtils.isNotEmpty;

@ServerSide
public class WindowsAuthenticationHelper {
  public static final String SSO_PRINCIPAL_KEY = NegotiateSecurityFilter.class.getName() + ".PRINCIPAL";
  public static final String BASIC_AUTH_PRINCIPAL_KEY = "ldap.windows.Principal";

  private static final Logger LOG = Loggers.get(WindowsAuthenticationHelper.class);

  private final AdConnectionHelper adConnectionHelper;
  private final IWindowsAuthProvider windowsAuthProvider;
  private final WindowsAuthSettings settings;

  public WindowsAuthenticationHelper(WindowsAuthSettings settings) {
    this(settings, new WindowsAuthProviderImpl(), new AdConnectionHelper());
  }

  WindowsAuthenticationHelper(WindowsAuthSettings settings, IWindowsAuthProvider windowsAuthProvider,
    AdConnectionHelper adConnectionHelper) {
    this.settings = settings;
    this.windowsAuthProvider = windowsAuthProvider;
    this.adConnectionHelper = adConnectionHelper;
  }

  /**
   * Checks if the request has valid {@link WindowsPrincipal}
   */
  public boolean isUserSsoAuthenticated(HttpServletRequest request) {
    checkNotNull(request, "request is null");

    return getWindowsPrincipal(request, WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY) != null;
  }

  /**
   * Returns {@link WindowsPrincipal} from given {@link HttpServletRequest}
   */
  public WindowsPrincipal getWindowsPrincipal(HttpServletRequest request, String windowsPrincipalKey) {
    checkNotNull(request, "request is null");
    checkNotNull(windowsPrincipalKey, "windowsPrincipalKey is null");

    WindowsPrincipal windowsPrincipal = null;
    HttpSession session = request.getSession();
    if (session != null) {
      Object attrValue = session.getAttribute(windowsPrincipalKey);
      if (attrValue instanceof WindowsPrincipal) {
        windowsPrincipal = (WindowsPrincipal) attrValue;
      }
    }

    return windowsPrincipal;
  }

  /**
   * Sets {@link WindowsPrincipal} in {@link HttpSession} of given {@link HttpServletRequest}
   */
  public void setWindowsPrincipalForBasicAuth(HttpServletRequest request, WindowsPrincipal windowsPrincipal) {
    checkNotNull(request, "request is null");
    checkNotNull(windowsPrincipal, "windowsPrincipal is null");

    HttpSession session = request.getSession();
    if (session != null) {
      session.setAttribute(BASIC_AUTH_PRINCIPAL_KEY, windowsPrincipal);
    }
  }

  /**
   * Removes basic auth principal key from{@link HttpSession} of given {@link HttpServletRequest}
   */
  public void removeWindowsPrincipalForBasicAuth(HttpServletRequest request) {
    checkNotNull(request, "request is null");

    HttpSession session = request.getSession();
    if (session != null) {
      session.removeAttribute(BASIC_AUTH_PRINCIPAL_KEY);
    }
  }

  /**
   * Removes sso principal key from {@link HttpSession} of given {@link HttpServletRequest}
   */
  public void removeWindowsPrincipalForSso(HttpServletRequest request) {
    checkNotNull(request, "request is null");

    HttpSession session = request.getSession();
    if (session != null) {
      session.removeAttribute(SSO_PRINCIPAL_KEY);
    }
  }

  /**
   * Authenticates the user using Windows LogonUser API
   */
  @CheckForNull
  public WindowsPrincipal logonUser(String userName, String password) {
    checkArgument(isNotEmpty(userName), "userName is null or empty.");
    checkArgument(isNotEmpty(password), "password is null or empty.");

    LOG.debug("Authenticating user: {}", userName);

    WindowsPrincipal windowsPrincipal = null;
    IWindowsIdentity windowsIdentity = null;
    try {
      windowsIdentity = windowsAuthProvider.logonUser(userName, password);
      if (windowsIdentity != null) {
        windowsPrincipal = new WindowsPrincipal(windowsIdentity);
      }
    } catch (Win32Exception win32Exception) {
      LOG.debug("User {} is not authenticated : {}", userName, win32Exception.getMessage());
    } finally {
      if (windowsIdentity != null) {
        windowsIdentity.dispose();
      }
    }

    return windowsPrincipal;
  }

  /**
   * Gets the {@link UserDetails} for the given {@link WindowsPrincipal} defined in {@link HttpServletRequest}.
   *
   * @return {@link UserDetails} for the given {@link WindowsPrincipal} or null if it is not found.
   */
  @CheckForNull
  public UserDetails getSsoUserDetails(HttpServletRequest request) {
    checkNotNull(request, "request is null");

    WindowsPrincipal windowsPrincipal = getWindowsPrincipal(request, WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY);
    return windowsPrincipal != null ? getUserDetails(windowsPrincipal.getName()) : null;
  }

  /**
   * Gets the {@link UserDetails} for the given domain user.
   *
   * @param userName The user name of the user.
   * @return {@link UserDetails} for the given domain user or null if the domain user is not found
   */
  @CheckForNull
  public UserDetails getUserDetails(String userName) {
    checkArgument(isNotEmpty(userName), "userName is null or empty.");

    LOG.debug("Getting details for user: {}", userName);
    UserDetails userDetails = null;
    IWindowsAccount windowsAccount = getWindowsAccount(userName);
    if (windowsAccount != null) {
      userDetails = getUserDetails(windowsAccount);
    }

    if (userDetails == null) {
      LOG.debug("Unable to get details for user {}", userName);
    } else {
      LOG.debug("Details for user {}: {}", userName, userDetails);
    }

    return userDetails;
  }

  /**
   * Retrieves the group information for the given {@link WindowsPrincipal}.
   *
   * @return A {@link Collection} of groups the user is member of.
   */
  public Collection<String> getUserGroups(WindowsPrincipal windowsPrincipal) {
    checkNotNull(windowsPrincipal, "windowsPrincipal is null");

    LOG.debug("Getting groups for user: {}", windowsPrincipal.getName());

    HashSet<String> groups = new HashSet<>();
    if (settings.getIsLdapWindowsCompatibilityModeEnabled()) {
      IWindowsAccount windowsAccount = getWindowsAccount(windowsPrincipal.getName());
      if (windowsAccount != null) {
        groups.addAll(getCompatibilityModeAdUserGroups(windowsAccount));
      }
    } else {
      Map<String, WindowsAccount> groupsMap = windowsPrincipal.getGroups();
      for (WindowsAccount group : groupsMap.values()) {
        groups.add(getWindowsAccountName(group, settings.getIsSonarAuthenticatorGroupDownCase()));
      }
    }

    LOG.debug("Groups for the user {} : {}", windowsPrincipal.getName(), groups);

    return groups;
  }

  UserDetails getUserDetails(IWindowsAccount windowsAccount) {
    UserDetails userDetails = new UserDetails();

    String windowsAccountName = getWindowsAccountName(new WindowsAccount(windowsAccount),
      settings.getIsSonarAuthenticatorLoginDownCase());
    userDetails.setUserId(windowsAccountName);

    Map<String, String> adUserDetails = getAdUserDetails(windowsAccount.getDomain(), windowsAccount.getName());
    if (!adUserDetails.isEmpty()) {
      userDetails.setName(adUserDetails.get(AdConnectionHelper.COMMON_NAME_ATTRIBUTE));
      userDetails.setEmail(adUserDetails.get(AdConnectionHelper.MAIL_ATTRIBUTE));
    } else {
      LOG.debug("Unable to get name and email for user: {}", windowsAccount.getFqn());
    }

    return userDetails;
  }

  // Returns the collection of user group name when the plugin is running under compatibility mode.
  private Collection<String> getCompatibilityModeAdUserGroups(IWindowsAccount windowsAccount) {
    Collection<String> userGroups = new ArrayList<>();

    Collection<String> adUserGroups = adConnectionHelper.getUserGroupsInDomain(windowsAccount.getDomain(),
      windowsAccount.getName(), settings.getGroupIdAttribute());
    if (adUserGroups != null) {
      userGroups.addAll(adUserGroups);
    } else {
      LOG.debug("Unable to get groups for the user: {}", windowsAccount.getFqn());
    }

    return userGroups;
  }

  @CheckForNull
  private IWindowsAccount getWindowsAccount(String userName) {
    IWindowsAccount windowsAccount = null;
    try {
      windowsAccount = windowsAuthProvider.lookupAccount(userName);

    } catch (Win32Exception win32Exception) {
      LOG.debug("User {} is not found: {}", userName, win32Exception.getMessage());
    }

    return windowsAccount;
  }

  private Map<String, String> getAdUserDetails(String domainName, String name) {
    Collection<String> requestedDetails = new ArrayList<>();
    requestedDetails.add(AdConnectionHelper.COMMON_NAME_ATTRIBUTE);
    requestedDetails.add(AdConnectionHelper.MAIL_ATTRIBUTE);
    return adConnectionHelper.getUserDetails(domainName, name, requestedDetails);
  }

  private String getWindowsAccountName(WindowsAccount windowsAccount, boolean isLowerCase) {
    String windowsAccountName;

    if (settings.getIsLdapWindowsCompatibilityModeEnabled()) {
      windowsAccountName = windowsAccount.getName();
    } else {
      windowsAccountName = windowsAccount.getName() + "@" + windowsAccount.getDomain();
    }

    if (isLowerCase) {
      windowsAccountName = windowsAccountName.toLowerCase();
    }

    return windowsAccountName;
  }
}
