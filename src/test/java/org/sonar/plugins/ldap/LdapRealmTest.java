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

import org.junit.Test;
import org.sonar.api.config.Settings;
import org.sonar.api.security.ExternalGroupsProvider;
import org.sonar.api.security.ExternalUsersProvider;
import org.sonar.api.security.LoginPasswordAuthenticator;
import org.sonar.api.utils.SonarException;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class LdapRealmTest {

  @Test
  public void test() {
    Settings settings = new Settings()
        .setProperty("ldap.url", "ldap://localhost");
    LdapRealm realm = new LdapRealm(settings);
    assertThat(realm.getName(), equalTo("LDAP"));
    try {
      realm.init();
      fail();
    } catch (SonarException e) {
      assertThat(e.getMessage(), containsString("Unable to open LDAP connection"));
    }
    assertThat(realm.getAuthenticator(), allOf(instanceOf(LoginPasswordAuthenticator.class), instanceOf(LdapAuthenticator.class)));
    assertThat(realm.getUsersProvider(), allOf(instanceOf(ExternalUsersProvider.class), instanceOf(LdapUsersProvider.class)));
    assertThat(realm.getGroupsProvider(), allOf(instanceOf(ExternalGroupsProvider.class), instanceOf(LdapGroupsProvider.class)));
  }

}
