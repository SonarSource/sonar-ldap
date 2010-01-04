/*
 * Copyright (C) 2009
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
