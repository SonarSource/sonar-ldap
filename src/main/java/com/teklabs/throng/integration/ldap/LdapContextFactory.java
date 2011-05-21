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

package com.teklabs.throng.integration.ldap;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;
import java.util.Properties;

/**
 * LDAP Context Factory.
 *
 * @author Evgeny Mandrikov
 */
public class LdapContextFactory {
  public static final String DEFAULT_AUTHENTICATION = "simple";
  public static final String DEFAULT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
  public static final String DEFAULT_REFERRAL = "follow";

  protected static final String GSSAPI_METHOD = "GSSAPI";
  protected static final String DIGEST_MD5_METHOD = "DIGEST-MD5";
  protected static final String CRAM_MD5_METHOD = "CRAM-MD5";

  /**
   * The Sun LDAP property used to enable connection pooling. This is used in the default implementation to enable
   * LDAP connection pooling.
   */
  private static final String SUN_CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";

  private static final String SASL_REALM_PROPERTY = "java.naming.security.sasl.realm";

  private String providerUrl = null;
  private String authentication = DEFAULT_AUTHENTICATION;
  private String factory = DEFAULT_FACTORY;
  private String referral = DEFAULT_REFERRAL;
  private String username = null;
  private String password = null;
  private String realm = null;

  /**
   * Creates a new instance of LdapContextFactory with specified LDAP url.
   *
   * @param providerUrl LDAP url
   */
  public LdapContextFactory(String providerUrl) {
    if (providerUrl == null) {
      throw new IllegalArgumentException("LDAP URL is not set");
    } else {
      this.providerUrl = providerUrl;
    }
  }

  /**
   * Returns InitialDirContext for Bind.
   *
   * @return InitialDirContext for Bind
   * @throws NamingException if a naming exception is encountered
   */
  public InitialDirContext getInitialDirContext() throws NamingException {
    return getInitialDirContext(username, password, true);
  }

  /**
   * Returns InitialDirContext for specified principal.
   *
   * @param principal   principal
   * @param credentials credentials
   * @return InitialDirContext for specified principal
   * @throws NamingException if a naming exception is encountered
   */
  public InitialDirContext getInitialDirContext(String principal, String credentials) throws NamingException {
    return getInitialDirContext(principal, credentials, false);
  }

  /**
   * Returns InitialDirContext for specified principal with specified pooling property.
   *
   * @param principal   principal
   * @param credentials credentials
   * @param pooling     true, if pooling should be enabled
   * @return InitialDirContext for specified principal with specified pooling property
   * @throws NamingException if a naming exception is encountered
   */
  public InitialDirContext getInitialDirContext(String principal, String credentials, boolean pooling) throws NamingException {
    if (LdapHelper.LOG.isDebugEnabled()) {
      LdapHelper.LOG.debug(
          "Initializing LDAP context using URL [" + providerUrl + "] and username [" + principal + "] " +
              "with pooling [" + (pooling ? "enabled" : "disabled") + "]");
    }
    return new InitialLdapContext(getEnvironment(principal, credentials, pooling), null);
  }

  /**
   * Returns environment properties for specified principal with specified pooling property.
   *
   * @param principal   principal
   * @param credentials credentials
   * @param pooling     true, if pooling should be enabled
   * @return environment properties
   */
  private Properties getEnvironment(String principal, String credentials, boolean pooling) {
    Properties env = new Properties();

    env.put(Context.SECURITY_AUTHENTICATION, authentication);

    if (principal != null) {
      env.put(Context.SECURITY_PRINCIPAL, principal);
    }
    if (credentials != null) {
      env.put(Context.SECURITY_CREDENTIALS, credentials);
    }

    if (realm != null) {
      env.put(SASL_REALM_PROPERTY, realm);
    }

    if (pooling) {
      // Enable connection pooling
      env.put(SUN_CONNECTION_POOLING_PROPERTY, "true");
    }

    env.put(Context.INITIAL_CONTEXT_FACTORY, factory);
    env.put(Context.PROVIDER_URL, providerUrl);
    env.put(Context.REFERRAL, referral);

    return env;
  }

  /**
   * Returns LDAP url (eg: ldap://localhost:10389).
   *
   * @return LDAP url
   */
  public String getProviderUrl() {
    return providerUrl;
  }

  /**
   * Returns context factory class.
   *
   * @return context factory class
   */
  public String getFactory() {
    return factory;
  }

  /**
   * Sets context factory class.
   *
   * @param factory context factory class
   */
  public void setFactory(String factory) {
    this.factory = factory;
  }

  /**
   * Sets Bind DN.
   *
   * @param username Bind DN
   */
  public void setUsername(String username) {
    this.username = username;
  }

  /**
   * Returns Bind DN.
   *
   * @return Bind DN
   */
  public String getUsername() {
    return username;
  }

  /**
   * Sets Bind Password.
   *
   * @param password Bind Password
   */
  public void setPassword(String password) {
    this.password = password;
  }

  /**
   * Returns authentication method (eg: simple).
   *
   * @return authentication method
   */
  public String getAuthentication() {
    return authentication;
  }

  /**
   * Sets authentication method (eg: simple).
   *
   * @param authentication authentication method
   */
  public void setAuthentication(String authentication) {
    this.authentication = authentication;
  }

  /**
   * Returns LDAP realm (eg: example.org).
   *
   * @return LDAP realm
   */
  public String getRealm() {
    return realm;
  }

  /**
   * Sets LDAP realm (eg: example.org).
   *
   * @param realm LDAP realm
   */
  public void setRealm(String realm) {
    this.realm = realm;
  }
}
