package com.teklabs.throng.integration.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * @author Evgeny Mandrikov
 */
public final class LdapHelper {
    public static final Logger LOG = LoggerFactory.getLogger("com.teklabs.sonar.plugins.ldap");

    /**
     * Hide utility-class constructor.
     */
    private LdapHelper() {
    }

    public static void closeContext(Context context) {
        try {
            if (context != null) {
                context.close();
            }
        } catch (Exception e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Can not close LDAP context", e);
            }
        }
    }

    /**
     * Get the DNS domain (eg: example.org).
     *
     * @return DNS domain
     * @throws java.net.UnknownHostException if unable to determine DNS domain
     */
    public static String getDnsDomain() throws UnknownHostException {
        String result = null;
        String localhost = InetAddress.getLocalHost().getCanonicalHostName();
        String[] parts = localhost.split("[.]");
        if (parts.length > 1) {
            // TODO Godin: is it true for eg "godin.usr.example.org"
            result = parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return result;
    }

    /**
     * Get the DNS DN domain (eg: dc=example,dc=org).
     *
     * @param domain DNS domain
     * @return DNS DN domain
     */
    public static String getDnsDomainDn(String domain) {
        StringBuilder result = new StringBuilder();
        String[] domainPart = domain.split("[.]");
        for (int i = 0; i < domainPart.length; i++) {
            result.append(i > 0 ? "," : "").append("dc=").append(domainPart[i]);
        }
        return result.toString();
    }

    /**
     * Get LDAP server (eg: ldap.example.org:389).
     *
     * @param domain DNS domain
     * @return LDAP server
     */
    public static String getLdapServer(String domain) {
        // get Active Directory servers from DNS
        String server = null;
        try {
            DirContext lDnsCtx = new InitialDirContext();
            Attributes lSrvAttrs = lDnsCtx.getAttributes("dns:/_ldap._tcp." + domain, new String[]{"srv"});
            Attribute serversAttribute = lSrvAttrs.get("srv");
            NamingEnumeration lEnum = serversAttribute.getAll();
            // TODO Godin: There is can be more than one srv record
            while (lEnum.hasMore()) {
                String srvRecord = (String) lEnum.next();
                String[] srvData = srvRecord.split(" ");

                String target = srvData[3].endsWith(".") ?
                        srvData[3].substring(0, srvData[3].length() - 1) :
                        srvData[3];
                String port = srvData[2];

                server = "ldap://" + target + ":" + port;
            }
        } catch (NamingException e) {
            LOG.error("Unable to determine ldap server", e);
        }
        return server;
    }
}
