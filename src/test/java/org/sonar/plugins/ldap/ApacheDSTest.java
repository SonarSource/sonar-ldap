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

import com.teklabs.throng.integration.ldap.ApacheDSTestServer;
import com.teklabs.throng.integration.ldap.LdapHelper;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

/**
 * @author Evgeny Mandrikov
 */
@RunWith(value = Parameterized.class)
public class ApacheDSTest {
  private static ApacheDSTestServer SERVER = new ApacheDSTestServer();

  private LdapAuthenticator authenticator;

  public ApacheDSTest(String config) throws ConfigurationException {
    LdapHelper.LOG.info("-------------------");
    LdapHelper.LOG.info("Config: " + config);
    LdapConfiguration configuration = new LdapConfiguration(
        new PropertiesConfiguration(getClass().getResource(config))
    );
    authenticator = new LdapAuthenticator(configuration);
  }

  @Parameterized.Parameters
  public static Collection data() {
    Object[][] data = new Object[][]{
        {"/conf/simple.properties"},
        {"/conf/bind.properties"},
        {"/conf/CRAM-MD5.properties"},
        {"/conf/DIGEST-MD5.properties"},
        {"/conf/GSSAPI.properties"},
//                {"/conf/sasl_mech.properties"}, // FIXME
    };
    return Arrays.asList(data);
  }

  @Test
  public void test() throws Exception {
    authenticator.init();
    Assert.assertFalse(authenticator.authenticate("godin", "incorrect"));
    Assert.assertTrue(authenticator.authenticate("godin", "secret1"));
    Assert.assertTrue(authenticator.authenticate("tester", "secret2"));
  }

  @BeforeClass
  public static void setUp() throws Exception {
    SERVER.setServerRoot("target/apacheds-work");
    SERVER.start();
    SERVER.initialize("/users-apacheds.ldif");

    String krbConfPath = ApacheDSTest.class.getResource("/conf/krb5.conf").toURI().getPath();
    LdapHelper.LOG.info("krbConfPath: " + krbConfPath);
    System.setProperty("java.security.krb5.conf", krbConfPath);
    System.setProperty("sun.security.krb5.debug", "true");
  }

  @AfterClass
  public static void tearDown() throws Exception {
    SERVER.stop();
  }

  public static void main(String[] args) throws Exception {
    setUp();
  }
}
