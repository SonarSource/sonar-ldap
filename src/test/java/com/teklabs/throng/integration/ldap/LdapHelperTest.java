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
