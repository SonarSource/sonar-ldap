package com.teklabs.throng.integration.ldap;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.InitialLdapContext;
import java.util.Hashtable;

/**
 * @author Evgeny Mandrikov
 */
public class LdapContextFactory {
    public static final String DEFAULT_AUTHENTICATION = "simple";
    public static final String DEFAULT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    protected static final String GSSAPI_METHOD = "GSSAPI";
    protected static final String DIGEST_MD5_METHOD = "DIGEST-MD5";
    protected static final String CRAM_MD5_METHOD = "CRAM-MD5";

    /**
     * The Sun LDAP property used to enable connection pooling. This is used in the default implementation to enable
     * LDAP connection pooling.
     */
    private static final String SUN_CONNECTION_POOLING_PROPERTY = "com.sun.jndi.ldap.connect.pool";

    private static final String SASL_REALM_PROPERTY = "java.naming.security.sasl.realm";

    private String authentication = DEFAULT_AUTHENTICATION;
    private String factory = DEFAULT_FACTORY;
    private String providerUrl = null;
    private String referral = "follow";
    private String username = null;
    private String password = null;
    private String realm = null;

    public LdapContextFactory(String providerUrl) {
        if (providerUrl == null) {
            throw new IllegalArgumentException("LDAP URL is not set");
        } else {
            this.providerUrl = providerUrl;
        }
    }

    public String getProviderUrl() {
        return providerUrl;
    }

    public String getFactory() {
        return factory;
    }

    public void setFactory(String factory) {
        this.factory = factory;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getAuthentication() {
        return authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public InitialDirContext getInitialDirContext() throws NamingException {
        return getInitialDirContext(username, password, true);
    }

    public InitialDirContext getInitialDirContext(String principal, String credentials) throws NamingException {
        return getInitialDirContext(principal, credentials, false);
    }

    public InitialDirContext getInitialDirContext(String principal, String credentials, boolean pooling) throws NamingException {
        if (LdapHelper.LOG.isDebugEnabled()) {
            LdapHelper.LOG.debug(
                    "Initializing LDAP context using URL [" + providerUrl + "] and username [" + principal + "] " +
                            "with pooling [" + (pooling ? "enabled" : "disabled") + "]");
        }
        return new InitialLdapContext(getEnvironment(principal, credentials, pooling), null);
    }

    private Hashtable<String, String> getEnvironment(String principal, String credentials, boolean pooling) {
        Hashtable<String, String> env = new Hashtable<String, String>();

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
}
