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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import java.net.InetAddress;
import java.net.UnknownHostException;

public final class LdapAutodiscovery {

  private static final Logger LOG = LoggerFactory.getLogger(LdapAutodiscovery.class);

  private LdapAutodiscovery() {
  }

  /**
   * Get the DNS domain name (eg: example.org).
   *
   * @return DNS domain
   * @throws java.net.UnknownHostException if unable to determine DNS domain
   */
  public static String getDnsDomainName() throws UnknownHostException {
    return getDnsDomainName(InetAddress.getLocalHost().getCanonicalHostName());
  }

  /**
   * Extracts DNS domain name from Fully Qualified Domain Name.
   *
   * @param fqdn Fully Qualified Domain Name
   * @return DNS domain name or null, if can't be extracted
   */
  public static String getDnsDomainName(String fqdn) {
    if (fqdn.indexOf('.') == -1) {
      return null;
    }
    return fqdn.substring(fqdn.indexOf('.') + 1);
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
      Attributes lSrvAttrs = lDnsCtx.getAttributes("dns:/_ldap._tcp." + domain, new String[] {"srv"});
      Attribute serversAttribute = lSrvAttrs.get("srv");
      NamingEnumeration lEnum = serversAttribute.getAll();
      // TODO Godin: There is can be more than one SRV record
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
      LOG.error("Unable to determine LDAP server from DNS", e);
    }
    return server;
  }

}
