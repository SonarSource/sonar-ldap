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

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class LdapGroupMappingTest {

  @Test
  public void defaults() {
    LdapGroupMapping groupMapping = new LdapGroupMapping(new Settings());

    assertThat(groupMapping.getBaseDn(), equalTo(null));
    assertThat(groupMapping.getObjectClass(), equalTo("groupOfUniqueNames"));
    assertThat(groupMapping.getIdAttribute(), equalTo("cn"));
    assertThat(groupMapping.getMemberAttribute(), equalTo("uniqueMember"));
    assertThat(groupMapping.getMemberFormat(), equalTo(null));

    assertThat(groupMapping.toString(), equalTo("LdapGroupMapping{" +
      "baseDn=null," +
      " objectClass=groupOfUniqueNames," +
      " idAttribute=cn," +
      " memberAttribute=uniqueMember," +
      " memberFormat=null}"));
  }

  @Test
  public void test() {
    Settings settings = new Settings()
        .setProperty("ldap.group.baseDn", "ou=groups,o=mycompany")
        .setProperty("ldap.group.objectClass", "groupOfUniqueNames")
        .setProperty("ldap.group.idAttribute", "cn")
        .setProperty("ldap.group.memberAttribute", "uniqueMember")
        .setProperty("ldap.group.memberFormat", "uid=$username,ou=users,o=mycompany");

    LdapGroupMapping groupMapping = new LdapGroupMapping(settings);
    LdapSearch search = groupMapping.createSearch(null, "tester");
    assertThat(search.getBaseDn(), equalTo("ou=groups,o=mycompany"));
    assertThat(search.getRequest(), equalTo("(&(objectClass=groupOfUniqueNames)(uniqueMember={0}))"));
    assertThat(search.getParameters(), equalTo(new String[] {"uid=tester,ou=users,o=mycompany"}));
    assertThat(search.getReturningAttributes(), equalTo(new String[] {"cn"}));

    assertThat(groupMapping.toString(), equalTo("LdapGroupMapping{" +
      "baseDn=ou=groups,o=mycompany," +
      " objectClass=groupOfUniqueNames," +
      " idAttribute=cn," +
      " memberAttribute=uniqueMember," +
      " memberFormat=uid=$username,ou=users,o=mycompany}"));
  }
}
