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

import org.sonar.api.security.Authenticator;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.SecurityRealm;

public class WindowsSecurityRealm extends SecurityRealm {

  // Keeping the Realm's NAME as "LDAP" to avoid having different realm name for the same plugin
  protected static final String NAME = "LDAP";

  private final WindowsAuthenticator windowsAuthenticator;
  private final WindowsUsersProvider windowsUsersProvider;
  private final WindowsGroupsProvider windowsGroupsProvider;

  public WindowsSecurityRealm(WindowsAuthenticationHelper windowsAuthenticationHelper) {
    this.windowsAuthenticator = new WindowsAuthenticator(windowsAuthenticationHelper);
    this.windowsUsersProvider = new WindowsUsersProvider(windowsAuthenticationHelper);
    this.windowsGroupsProvider = new WindowsGroupsProvider(windowsAuthenticationHelper);
  }

  @Override
  public Authenticator doGetAuthenticator() {
    return windowsAuthenticator;
  }

  @Override
  public ExternalUsersProvider getUsersProvider() {
    return windowsUsersProvider;
  }

  @Override
  public ExternalGroupsProvider getGroupsProvider() {
    return windowsGroupsProvider;
  }

  @Override
  public String getName() {
    return NAME;
  }
}
