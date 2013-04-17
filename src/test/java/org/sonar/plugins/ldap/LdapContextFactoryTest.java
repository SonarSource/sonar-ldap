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
import org.sonar.plugins.ldap.server.LdapServer;

import javax.naming.AuthenticationException;
import javax.naming.NamingException;
import javax.security.sasl.SaslException;

import java.util.Map;

import static org.fest.assertions.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.sonar.plugins.ldap.LdapContextFactory.CRAM_MD5_METHOD;
import static org.sonar.plugins.ldap.LdapContextFactory.DIGEST_MD5_METHOD;
import static org.sonar.plugins.ldap.LdapContextFactory.GSSAPI_METHOD;

public class LdapContextFactoryTest {

  private static String REALM = "example.org";

  private static String BIND_DN = "cn=bind,ou=users,dc=example,dc=org";

  /**
   * This value must match value of attribute "uid" for {@link #BIND_DN} in "users.example.org.ldif"
   */
  private static String USERNAME = "sonar";

  /**
   * This value must match value of attribute "userpassword" for {@link #BIND_DN} in "users.example.org.ldif"
   */
  private static String PASSWORD = "bindpassword";

  @ClassRule
  public static LdapServer server = new LdapServer("/users.example.org.ldif");

  @Test
  public void simpleBind() throws Exception {
    Map<String, LdapContextFactory> contextFactories = LdapContextFactories.createForAnonymousAccess(server.getUrl());
      LdapContextFactory contextFactory = contextFactories.get(LdapContextFactories.LDAP);
    contextFactory.testConnection();
    contextFactory.createBindContext();
    assertThat(contextFactory.isSasl()).isFalse();
    assertThat(contextFactory.isGssapi()).isFalse();
    assertThat(contextFactory.toString()).isEqualTo("LdapContextFactory{" +
        "url=ldap://localhost:1024," +
        " authentication=simple," +
        " factory=com.sun.jndi.ldap.LdapCtxFactory," +
        " bindDn=null," +
        " realm=null}");

    server.disableAnonymousAccess();
    try {
      LdapContextFactories.createForAnonymousAccess(server.getUrl()).get(LdapContextFactories.LDAP)
          .createBindContext();
      fail();
    } catch (NamingException e) {
      // ok - anonymous access disabled
      assertThat(e).isInstanceOf(AuthenticationException.class);
      assertThat(e.getMessage()).contains("INVALID_CREDENTIALS");
    }
    LdapContextFactories.createForSimpleBind(server.getUrl(), BIND_DN, PASSWORD).get(LdapContextFactories.LDAP)
        .createBindContext();
  }

  @Test
  public void cram_md5() throws Exception {
    Map<String, LdapContextFactory> contextFactories = LdapContextFactories.createForAuthenticationMethod(server.getUrl(), CRAM_MD5_METHOD, REALM, USERNAME, PASSWORD);
      LdapContextFactory contextFactory = contextFactories.get(LdapContextFactories.LDAP);
    contextFactory.testConnection();
    contextFactory.createBindContext();
    assertThat(contextFactory.isSasl()).isTrue();
    assertThat(contextFactory.isGssapi()).isFalse();
    assertThat(contextFactory.toString()).isEqualTo("LdapContextFactory{" +
        "url=ldap://localhost:1024," +
        " authentication=CRAM-MD5," +
        " factory=com.sun.jndi.ldap.LdapCtxFactory," +
        " bindDn=sonar," +
        " realm=example.org}");

    try {
      LdapContextFactories.createForAuthenticationMethod(server.getUrl(), LdapContextFactory.CRAM_MD5_METHOD, REALM, USERNAME, "wrong").get(LdapContextFactories.LDAP)
          .createBindContext();
      fail();
    } catch (NamingException e) {
      // ok
      assertThat(e).isInstanceOf(AuthenticationException.class);
      assertThat(e.getMessage()).contains("INVALID_CREDENTIALS");
    }
    try {
      LdapContextFactories.createForAuthenticationMethod(server.getUrl(), LdapContextFactory.CRAM_MD5_METHOD, REALM, null, null).get(LdapContextFactories.LDAP)
          .createBindContext();
      fail();
    } catch (NamingException e) {
      // ok, but just to be sure that we used CRAM-MD5:
      assertThat(e).isInstanceOf(AuthenticationException.class);
      assertThat(e.getRootCause()).isInstanceOf(SaslException.class);
      assertThat(e.getRootCause().getMessage()).contains("CRAM-MD5: authentication ID and password must be specified");
    }
  }

  @Test
  public void digest_md5() throws Exception {
    Map<String, LdapContextFactory> contextFactories = LdapContextFactories.createForAuthenticationMethod(server.getUrl(), DIGEST_MD5_METHOD, REALM, USERNAME, PASSWORD);
      LdapContextFactory contextFactory = contextFactories.get(LdapContextFactories.LDAP);
    contextFactory.testConnection();
    contextFactory.createBindContext();
    assertThat(contextFactory.isSasl()).isTrue();
    assertThat(contextFactory.isGssapi()).isFalse();
    assertThat(contextFactory.toString()).isEqualTo("LdapContextFactory{" +
        "url=ldap://localhost:1024," +
        " authentication=DIGEST-MD5," +
        " factory=com.sun.jndi.ldap.LdapCtxFactory," +
        " bindDn=sonar," +
        " realm=example.org}");

    try {
      LdapContextFactories.createForAuthenticationMethod(server.getUrl(), DIGEST_MD5_METHOD, REALM, USERNAME, "wrongpassword").get(LdapContextFactories.LDAP)
          .createBindContext();
      fail();
    } catch (NamingException e) {
      // ok
      assertThat(e).isInstanceOf(AuthenticationException.class);
      assertThat(e.getMessage()).contains("INVALID_CREDENTIALS");
    }
    try {
      LdapContextFactories.createForAuthenticationMethod(server.getUrl(), DIGEST_MD5_METHOD, "wrong", USERNAME, PASSWORD).get(LdapContextFactories.LDAP)
          .createBindContext();
      fail();
    } catch (NamingException e) {
      // ok
      assertThat(e).isInstanceOf(AuthenticationException.class);
      assertThat(e.getMessage()).contains("Nonexistent realm: wrong");
    }
    try {
      LdapContextFactories.createForAuthenticationMethod(server.getUrl(), DIGEST_MD5_METHOD, REALM, null, null).get(LdapContextFactories.LDAP)
          .createBindContext();
      fail();
    } catch (NamingException e) {
      // ok, but just to be sure that we used DIGEST-MD5:
      assertThat(e).isInstanceOf(AuthenticationException.class);
      assertThat(e.getRootCause()).isInstanceOf(SaslException.class);
      assertThat(e.getRootCause().getMessage()).contains("DIGEST-MD5: authentication ID and password must be specified");
    }
  }

  @Test
  public void gssApi() throws Exception {
    LdapContextFactory contextFactory = LdapContextFactories.createForAuthenticationMethod(server.getUrl(), GSSAPI_METHOD, REALM, USERNAME, PASSWORD).get(LdapContextFactories.LDAP);
    assertThat(contextFactory.isSasl()).isTrue();
    assertThat(contextFactory.isGssapi()).isTrue();
    assertThat(contextFactory.toString()).isEqualTo("LdapContextFactory{" +
        "url=ldap://localhost:1024," +
        " authentication=GSSAPI," +
        " factory=com.sun.jndi.ldap.LdapCtxFactory," +
        " bindDn=sonar," +
        " realm=example.org}");
  }

}
