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

import org.junit.ClassRule;
import org.junit.Test;
import org.sonar.api.config.Settings;
import org.sonar.api.security.UserDetails;
import org.sonar.plugins.ldap.server.LdapServer;

import static org.fest.assertions.Assertions.assertThat;

public class LdapUsersProviderTest {
  /**
   * A reference to the original ldif file
   */
  public static final String USERS_EXAMPLE_ORG_LDIF = "/users.example.org.ldif";
  /**
   * A reference to an aditional ldif file.
   */
  public static final String USERS_INFOSUPPORT_COM_LDIF = "/users.infosupport.com.ldif";

  @ClassRule
  public static LdapServer exampleServer = new LdapServer(
	  USERS_EXAMPLE_ORG_LDIF);
  @ClassRule
  public static LdapServer infosupportServer = new LdapServer(
	  USERS_INFOSUPPORT_COM_LDIF, "infosupport.com", "dc=infosupport,dc=com");

  @Test
  public void test() throws Exception {
	Settings settings = LdapSettingsFactory
		.generateSimpleAnonymousAccessSettings(exampleServer, infosupportServer);
	LdapSettingsManager settingsManager = new LdapSettingsManager(settings);
	LdapUsersProvider usersProvider = new LdapUsersProvider(
		settingsManager.getContextFactories(),
		settingsManager.getUserMappings());

	UserDetails details;

	details = usersProvider.doGetUserDetails("godin");
	assertThat(details.getName()).isEqualTo("Evgeny Mandrikov");
	assertThat(details.getEmail()).isEqualTo("godin@example.org");

	details = usersProvider.doGetUserDetails("tester");
	assertThat(details.getName()).isEqualTo("Tester Testerovich");
	assertThat(details.getEmail()).isEqualTo("tester@example.org");

	details = usersProvider.doGetUserDetails("without_email");
	assertThat(details.getName()).isEqualTo("Without Email");
	assertThat(details.getEmail()).isEqualTo("");

	details = usersProvider.doGetUserDetails("notfound");
	assertThat(details).isNull();

	details = usersProvider.doGetUserDetails("robby");
	assertThat(details.getName()).isEqualTo("Robby Developer");
	assertThat(details.getEmail()).isEqualTo("rd@infosupport.com");

	details = usersProvider.doGetUserDetails("testerInfo");
	assertThat(details.getName()).isEqualTo("Tester Testerovich");
	assertThat(details.getEmail()).isEqualTo("tester@infosupport.com");
  }

}
