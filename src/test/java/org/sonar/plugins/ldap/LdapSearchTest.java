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

import com.google.common.collect.Iterators;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.plugins.ldap.server.LdapServer;

import javax.naming.NamingException;
import javax.naming.directory.SearchControls;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

public class LdapSearchTest {

  @ClassRule
  public static LdapServer server = new LdapServer("/users.ldif");

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private static LdapContextFactory contextFactory;

  @BeforeClass
  public static void init() {
    contextFactory = LdapContextFactories.createForAnonymousAccess(server.getUrl());
  }

  @Test
  public void subtreeSearch() throws Exception {
    LdapSearch search = new LdapSearch(contextFactory)
        .setBaseDn("dc=example,dc=org")
        .setRequest("(objectClass={0})")
        .setParameters("inetOrgPerson")
        .returns("objectClass");

    assertThat(search.getBaseDn(), is("dc=example,dc=org"));
    assertThat(search.getScope(), is(SearchControls.SUBTREE_SCOPE));
    assertThat(search.getRequest(), is("(objectClass={0})"));
    assertThat(search.getParameters(), is(new String[] {"inetOrgPerson"}));
    assertThat(search.getReturningAttributes(), is(new String[] {"objectClass"}));
    assertThat(search.toString(), is("LdapSearch{baseDn=dc=example,dc=org, scope=subtree, request=(objectClass={0}), parameters=[inetOrgPerson], attributes=[objectClass]}"));
    assertThat(Iterators.size(Iterators.forEnumeration(search.find())), is(3));
    thrown.expect(NamingException.class);
    thrown.expectMessage("Non unique result for " + search.toString());
    search.findUnique();
  }

  @Test
  public void oneLevelSearch() throws Exception {
    LdapSearch search = new LdapSearch(contextFactory)
        .setBaseDn("dc=example,dc=org")
        .setScope(SearchControls.ONELEVEL_SCOPE)
        .setRequest("(objectClass={0})")
        .setParameters("inetOrgPerson")
        .returns("cn");

    assertThat(search.getBaseDn(), is("dc=example,dc=org"));
    assertThat(search.getScope(), is(SearchControls.ONELEVEL_SCOPE));
    assertThat(search.getRequest(), is("(objectClass={0})"));
    assertThat(search.getParameters(), is(new String[] {"inetOrgPerson"}));
    assertThat(search.getReturningAttributes(), is(new String[] {"cn"}));
    assertThat(search.toString(), is("LdapSearch{baseDn=dc=example,dc=org, scope=onelevel, request=(objectClass={0}), parameters=[inetOrgPerson], attributes=[cn]}"));
    assertThat(Iterators.size(Iterators.forEnumeration(search.find())), is(0));
    assertThat(search.findUnique(), nullValue());
  }

  @Test
  public void objectSearch() throws Exception {
    LdapSearch search = new LdapSearch(contextFactory)
        .setBaseDn("cn=bind,ou=users,dc=example,dc=org")
        .setScope(SearchControls.OBJECT_SCOPE)
        .setRequest("(objectClass={0})")
        .setParameters("uidObject")
        .returns("uid");

    assertThat(search.getBaseDn(), is("cn=bind,ou=users,dc=example,dc=org"));
    assertThat(search.getScope(), is(SearchControls.OBJECT_SCOPE));
    assertThat(search.getRequest(), is("(objectClass={0})"));
    assertThat(search.getParameters(), is(new String[] {"uidObject"}));
    assertThat(search.getReturningAttributes(), is(new String[] {"uid"}));
    assertThat(search.toString(), is("LdapSearch{baseDn=cn=bind,ou=users,dc=example,dc=org, scope=object, request=(objectClass={0}), parameters=[uidObject], attributes=[uid]}"));
    assertThat(Iterators.size(Iterators.forEnumeration(search.find())), is(1));
    assertThat(search.findUnique(), not(nullValue()));
  }

}
