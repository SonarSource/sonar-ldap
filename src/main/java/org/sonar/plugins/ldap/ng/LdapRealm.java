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
package org.sonar.plugins.ldap.ng;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.LoginPasswordAuthenticator;
import org.sonar.api.security.Realm;
import org.sonar.api.utils.SonarException;

/**
 * @author Evgeny Mandrikov
 */
public class LdapRealm extends Realm {

  private static final Logger LOG = LoggerFactory.getLogger(LdapRealm.class);

  private final Settings settings;

  private LdapUsersProvider usersProvider;
  private LdapGroupsProvider groupsProvider;
  private LdapAuthenticator authenticator;

  public LdapRealm(Settings settings) {
    this.settings = settings;
  }

  @Override
  public String getName() {
    return "LDAP";
  }

  /**
   * Initializes LDAP realm and tests connection.
   *
   * @throws SonarException if a NamingException was thrown during test
   */
  @Override
  public void init() {
    LdapContextFactory contextFactory = new LdapContextFactory(settings);
    LOG.info("{}", contextFactory);
    LdapUserMapping userMapping = new LdapUserMapping(settings);
    LdapGroupMapping groupMapping = new LdapGroupMapping(settings);
    LOG.info("{}", userMapping);
    LOG.info("{}", groupMapping);
    usersProvider = new LdapUsersProvider(contextFactory, userMapping);
    groupsProvider = new LdapGroupsProvider(contextFactory, groupMapping);
    authenticator = new LdapAuthenticator(contextFactory, userMapping);
    contextFactory.testConnection();
  }

  @Override
  public LoginPasswordAuthenticator getAuthenticator() {
    return authenticator;
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
