/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.plugins.ldap;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import java.util.Properties;
import javax.annotation.Nullable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;
import org.apache.commons.lang.StringUtils;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

/**
 * @author Evgeny Mandrikov
 */
public class LdapContextFactory {

  private static final Logger LOG = Loggers.get(LdapContextFactory.class);
  private static final String DEFAULT_REFERRAL = "follow";

  @VisibleForTesting
  static final String AUTH_METHOD_GSSAPI = "GSSAPI";

  @VisibleForTesting
  static final String AUTH_METHOD_DIGEST_MD5 = "DIGEST-MD5";

  @VisibleForTesting
  static final String AUTH_METHOD_CRAM_MD5 = "CRAM-MD5";

  /**
   * The Sun LDAP property used to enable connection pooling. This is used in the default implementation to enable
   * LDAP connection pooling.
   */
  private static final String SUN_CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";

  private static final String SASL_REALM_PROPERTY = "java.naming.security.sasl.realm";

  private final String providerUrl;
  private final String authentication;
  private final String factory;
  private final String username;
  private final String password;
  private final String realm;

  public LdapContextFactory(LdapSettings settings, String settingsPrefix, String ldapUrl) {
    this.authentication = settings.getLdapAuthenticationOrDefault(settingsPrefix);
    this.factory = settings.getLdapContextFactoryOrDefault(settingsPrefix);
    this.realm = settings.getLdapRealm(settingsPrefix);
    this.providerUrl = ldapUrl;
    this.username = settings.getBindUserNameDn(settingsPrefix);
    this.password = settings.getBindPassword(settingsPrefix);
  }

  /**
   * Returns {@code InitialDirContext} for Bind user.
   */
  public InitialDirContext createBindContext() throws NamingException {
    return createInitialDirContext(username, password, true);
  }

  /**
   * Returns {@code InitialDirContext} for specified user.
   * Note that pooling intentionally disabled by this method.
   */
  public InitialDirContext createUserContext(String principal, String credentials) throws NamingException {
    return createInitialDirContext(principal, credentials, false);
  }

  private InitialDirContext createInitialDirContext(String principal, String credentials, boolean pooling) throws NamingException {
    return new InitialLdapContext(getEnvironment(principal, credentials, pooling), null);
  }

  private Properties getEnvironment(@Nullable String principal, @Nullable String credentials, boolean pooling) {
    Properties env = new Properties();
    env.put(Context.SECURITY_AUTHENTICATION, authentication);
    if (realm != null) {
      env.put(SASL_REALM_PROPERTY, realm);
    }
    if (pooling) {
      // Enable connection pooling
      env.put(SUN_CONNECTION_POOLING_PROPERTY, "true");
    }
    env.put(Context.INITIAL_CONTEXT_FACTORY, factory);
    env.put(Context.PROVIDER_URL, providerUrl);
    env.put(Context.REFERRAL, DEFAULT_REFERRAL);
    if (principal != null) {
      env.put(Context.SECURITY_PRINCIPAL, principal);
    }
    // Note: debug is intentionally was placed here - in order to not expose password in log
    LOG.debug("Initializing LDAP context {}", env);
    if (credentials != null) {
      env.put(Context.SECURITY_CREDENTIALS, credentials);
    }
    return env;
  }

  public boolean isSasl() {
    return AUTH_METHOD_DIGEST_MD5.equals(authentication) ||
      AUTH_METHOD_CRAM_MD5.equals(authentication) ||
      AUTH_METHOD_GSSAPI.equals(authentication);
  }

  public boolean isGssapi() {
    return AUTH_METHOD_GSSAPI.equals(authentication);
  }

  /**
   * Tests connection.
   *
   * @throws IllegalStateException if unable to open connection
   */
  public void testConnection() {
    if (StringUtils.isBlank(username) && isSasl()) {
      throw new IllegalArgumentException("When using SASL - property ldap.bindDn is required");
    }
    try {
      createBindContext();
      LOG.info("Test LDAP connection on {}: OK", providerUrl);
    } catch (NamingException e) {
      LOG.info("Test LDAP connection: FAIL");
      throw new IllegalStateException("Unable to open LDAP connection", e);
    }
  }

  public String getProviderUrl() {
    return providerUrl;
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
      .add("url", providerUrl)
      .add("authentication", authentication)
      .add("factory", factory)
      .add("bindDn", username)
      .add("realm", realm)
      .toString();
  }

}
