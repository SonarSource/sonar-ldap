package com.teklabs.throng.integration.ldap;

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Evgeny Mandrikov
 */
public final class LdapHelperTest {
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
