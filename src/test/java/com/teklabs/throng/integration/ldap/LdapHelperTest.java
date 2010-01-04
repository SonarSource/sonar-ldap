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

package com.teklabs.throng.integration.ldap;

import org.junit.Assert;
import org.junit.Test;

import java.net.UnknownHostException;

/**
 * @author Evgeny Mandrikov
 */
public final class LdapHelperTest {
    @Test
    public void testGetDnsDomain() throws UnknownHostException {
        Assert.assertEquals(
                null,
                LdapHelper.getDnsDomainName("localhost")
        );
        Assert.assertEquals(
                "example.org",
                LdapHelper.getDnsDomainName("godin.example.org")
        );
        Assert.assertEquals(
                "usr.example.org",
                LdapHelper.getDnsDomainName("godin.usr.example.org")
        );
    }

    @Test
    public void testGetDnsDomainDn() {
        Assert.assertEquals(
                "dc=example,dc=org",
                LdapHelper.getDnsDomainDn("example.org")
        );
    }

    @Test
    public void testGetLdapServer() {
        Assert.assertEquals(
                "ldap://ldap.teklabs.com:389",
                LdapHelper.getLdapServer("teklabs.com")
        );
    }
}
