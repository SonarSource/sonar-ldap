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

import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.config.Settings;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.LoginPasswordAuthenticator;
import org.sonar.api.security.SecurityRealm;

/**
 * @author Evgeny Mandrikov
 */
public class LdapRealm extends SecurityRealm {

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
   * @throws org.sonar.api.utils.SonarException if a NamingException was thrown during test
   */
  @Override
  public void init() {
    LdapContextFactory contextFactory = new LdapContextFactory(settings);
    LOG.info("{}", contextFactory);
    LdapUserMapping userMapping = new LdapUserMapping(settings);
    LOG.info("{}", userMapping);
    usersProvider = new LdapUsersProvider(contextFactory, userMapping);
    authenticator = new LdapAuthenticator(contextFactory, userMapping);
    LdapGroupMapping groupMapping = new LdapGroupMapping(settings);
    if (Strings.isNullOrEmpty(groupMapping.getBaseDn())) {
      LOG.info("Groups will not be synchronized, because property 'ldap.group.baseDn' is empty.");
    } else {
      LOG.info("{}", groupMapping);
      groupsProvider = new LdapGroupsProvider(contextFactory, userMapping, groupMapping);
    }
    contextFactory.testConnection();
  }

  @Override
  public LoginPasswordAuthenticator getLoginPasswordAuthenticator() {
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
