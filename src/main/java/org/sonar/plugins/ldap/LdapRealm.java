/*
 * Sonar LDAP Plugin
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
package org.sonar.plugins.ldap;

import java.util.Map;

import org.sonar.api.config.Settings;
import org.sonar.api.security.Authenticator;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.SecurityRealm;

/**
 * @author Evgeny Mandrikov
 */
public class LdapRealm extends SecurityRealm {

  private LdapUsersProvider usersProvider;
  private LdapGroupsProvider groupsProvider;
  private final LdapSettingsManager settingsManager;

  public LdapRealm(Settings settings) {
    settingsManager = new LdapSettingsManager(settings);
  }

  @Override
  public String getName() {
    return "LDAP";
  }

  /**
   * Initializes LDAP realm and tests connection.
   *
   * @throws org.sonar.api.utils.SonarException if a NamingException was thrown during test
   */
  @Override
  public void init() {

    Map<String, LdapContextFactory> contextFactories = settingsManager.getContextFactories();
    Map<String, LdapUserMapping> userMappings = settingsManager.getUserMappings();
    usersProvider = new LdapUsersProvider(contextFactories, userMappings);
    Map<String, LdapGroupMapping> groupMappings = settingsManager.getGroupMappings();
    if (!groupMappings.isEmpty()) {
      groupsProvider = new LdapGroupsProvider(contextFactories, userMappings, groupMappings);
    }
    for (LdapContextFactory contextFactory : contextFactories.values()) {
      contextFactory.testConnection();
    }
  }
  
  @Override
  public Authenticator doGetAuthenticator() {
    return new LdapAuthenticator(settingsManager.getContextFactories(), settingsManager.getUserMappings());
  }

  @Override
  public ExternalUsersProvider getUsersProvider() {
    return usersProvider;
  }

  @Override
  public ExternalGroupsProvider getGroupsProvider() {
    return groupsProvider;
  }

}
