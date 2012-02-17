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

import javax.naming.directory.SearchControls;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class LdapSearchTest {

  @Test
  public void test() {
    LdapSearch search = new LdapSearch(null)
        .setBaseDn("cn=users")
        .setRequest("(objectClass={0})")
        .setParameters("user")
        .returns("uid");
    assertThat("default scope", search.getScope(), is(SearchControls.SUBTREE_SCOPE));
    assertThat(search.toString(), is("LdapSearch{baseDn=cn=users, scope=subtree, request=(objectClass={0}), parameters=[user], attributes=[uid]}"));
  }

}
