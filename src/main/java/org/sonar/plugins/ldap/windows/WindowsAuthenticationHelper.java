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

import com.google.common.base.Preconditions;
import com.sun.jna.platform.win32.Win32Exception;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import javax.annotation.CheckForNull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.sonar.api.ServerExtension;
import org.sonar.api.security.UserDetails;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.sonar.plugins.ldap.windows.auth.PrincipalFormat;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import waffle.servlet.NegotiateSecurityFilter;
import waffle.servlet.WindowsPrincipal;
import waffle.windows.auth.IWindowsAccount;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.WindowsAccount;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

public class WindowsAuthenticationHelper implements ServerExtension {
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
    Preconditions.checkArgument(request != null, "request is null");

    return getWindowsPrincipal(request, WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY) != null;
  }

  /**
   * Returns {@link WindowsPrincipal} from given {@link HttpServletRequest}
   */
  public WindowsPrincipal getWindowsPrincipal(HttpServletRequest request, String windowsPrincipalKey) {
    Preconditions.checkArgument(request != null, "request is null");
    Preconditions.checkArgument(windowsPrincipalKey != null, "windowsPrincipalKey is null");

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
    Preconditions.checkArgument(request != null, "request is null");
    Preconditions.checkArgument(windowsPrincipal != null, "windowsPrincipal is null");

    HttpSession session = request.getSession();
    if (session != null) {
      session.setAttribute(BASIC_AUTH_PRINCIPAL_KEY, windowsPrincipal);
    }
  }

  /**
   * Removes basic auth principal key from{@link HttpSession} of given {@link HttpServletRequest}
   */
  public void removeWindowsPrincipalForBasicAuth(HttpServletRequest request) {
    Preconditions.checkArgument(request != null, "request is null");

    HttpSession session = request.getSession();
    if (session != null) {
      session.removeAttribute(BASIC_AUTH_PRINCIPAL_KEY);
    }
  }

  /**
   * Removes sso principal key from {@link HttpSession} of given {@link HttpServletRequest}
   */
  public void removeWindowsPrincipalForSso(HttpServletRequest request) {
    Preconditions.checkArgument(request != null, "request is null");

    HttpSession session = request.getSession();
    if (session != null) {
      session.removeAttribute(SSO_PRINCIPAL_KEY);
    }
  }

  /**
   * Authenticates the user using Windows LogonUser API
   */
  public WindowsPrincipal logonUser(final String userName, final String password) {
    if (userName == null || userName.isEmpty()) {
      throw new IllegalArgumentException("userName is null or empty.");
    }

    if (password == null || password.isEmpty()) {
      throw new IllegalArgumentException("password is null or empty.");
    }

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
  public UserDetails getSsoUserDetails(HttpServletRequest request) {
    Preconditions.checkArgument(request != null, "request is null");

    WindowsPrincipal windowsPrincipal = getWindowsPrincipal(request, WindowsAuthenticationHelper.SSO_PRINCIPAL_KEY);
    return windowsPrincipal != null ? getUserDetails(windowsPrincipal.getName()) : null;
  }

  /**
   * Gets the {@link UserDetails} for the given domain user.
   *
   * @param userName The user name of the user.
   * @return {@link UserDetails} for the given domain user or null if the domain user is not found
   */
  public UserDetails getUserDetails(final String userName) {
    if (userName == null || userName.isEmpty()) {
      throw new IllegalArgumentException("userName is null or empty.");
    }

    IWindowsAccount windowsAccount = getWindowsAccount(userName);
    return windowsAccount != null ? getSsoUserDetails(windowsAccount) : null;
  }

  /**
   * Retrieves the group information for the given {@link WindowsPrincipal}.
   *
   * @return A {@link Collection} of groups the user is member of.
   */
  public Collection<String> getUserGroups(WindowsPrincipal windowsPrincipal) {
    Preconditions.checkArgument(windowsPrincipal != null, "windowsPrincipal is null");

    LOG.debug("Getting groups for user: {}", windowsPrincipal.getName());

    HashSet<String> groups = new HashSet<>();
    Map<String, WindowsAccount> groupsMap = windowsPrincipal.getGroups();
    for (WindowsAccount windowsAccount : groupsMap.values()) {
      if (windowsAccount != null) {
        String groupName = getWindowsAccountName(windowsAccount, true);
        if (!groups.contains(groupName)) {
          groups.add(getWindowsAccountName(windowsAccount, true));
        }
      }
    }

    return groups;
  }

  UserDetails getSsoUserDetails(IWindowsAccount windowsAccount) {
    UserDetails userDetails = new UserDetails();

    String windowsAccountName = getWindowsAccountName(new WindowsAccount(windowsAccount), false);
    userDetails.setUserId(windowsAccountName);

    Map<String, String> adUserDetails = getAdUserDetails(windowsAccount.getDomain(), windowsAccount.getName());
    if (!adUserDetails.isEmpty()) {
      userDetails.setName(adUserDetails.get(AdConnectionHelper.COMMON_NAME_ATTRIBUTE));
      userDetails.setEmail(adUserDetails.get(AdConnectionHelper.MAIL_ATTRIBUTE));
    } else {
      LOG.debug("Unable to get Name and Email for user: {}", windowsAccount.getFqn());
    }

    return userDetails;
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

  private String getWindowsAccountName(WindowsAccount windowsAccount, boolean isGroup) {
    String windowsAccountName;

    PrincipalFormat principalFormat = isGroup ? settings.getUserGroupFormat() : settings.getUserIdFormat();
    switch (principalFormat) {
      case ULN:
        windowsAccountName = windowsAccount.getName();
        break;

      case UPN:
      default:
        windowsAccountName = windowsAccount.getName() + "@" + windowsAccount.getDomain();
        break;
    }

    boolean isLowerCaseConversionRequired = isGroup ? settings.getIsSonarAuthenticatorGroupDownCase() : settings.getIsSonarAuthenticatorLoginDownCase();
    if (isLowerCaseConversionRequired) {
      windowsAccountName = windowsAccountName.toLowerCase();
    }

    return windowsAccountName;
  }

}
