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

import org.apache.commons.lang.StringUtils;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import static com.teklabs.throng.integration.ldap.LdapContextFactory.*;

/**
 * @author Evgeny Mandrikov
 */
public class Ldap {
    public static final String DEFAULT_USER_OBJECT_CLASS = "inetOrgPerson";
    public static final String DEFAULT_LOGIN_ATTRIBUTE = "uid";

    private LdapContextFactory ldapContextFactory;
    private String baseDN = null;
    private String loginAttribute = DEFAULT_LOGIN_ATTRIBUTE;
    private String userObjectClass = DEFAULT_USER_OBJECT_CLASS;

    /**
     * Creates a new instance of Ldap with specified context factory.
     *
     * @param ldapContextFactory LDAP context factory
     */
    public Ldap(LdapContextFactory ldapContextFactory) {
        if (ldapContextFactory == null) {
            throw new IllegalArgumentException("LDAP context factory is not set");
        }
        this.ldapContextFactory = ldapContextFactory;
    }

    /**
     * Tests connection.
     *
     * @throws NamingException if a naming exception is encountered
     */
    public void testConnection() throws NamingException {
        if (StringUtils.isBlank(ldapContextFactory.getUsername()) && isSasl()) {
            LdapHelper.LOG.warn("Unable to test connection, if using SASL and no username specified");
        } else {
            LdapHelper.LOG.debug("Test connection");
            ldapContextFactory.getInitialDirContext();
        }
    }

    /**
     * Tries to authenticate specified user with specified password.
     *
     * @param login    login
     * @param password password
     * @return true, if user can be authenticated with specified password
     * @throws NamingException if a naming exception is encountered
     */
    public boolean authenticate(String login, String password) throws NamingException {
        String principal;
        // if we are authenticating against DIGEST-MD5 or CRAM-MD5 then username is not the DN
        if (isSasl()) {
            principal = login;
        } else {
            principal = getPrincipal(login);
        }
        if (GSSAPI_METHOD.equals(ldapContextFactory.getAuthentication())) {
            return StringUtils.isNotBlank(principal) && checkPasswordUsingGssapi(principal, password);
        }
        return StringUtils.isNotBlank(principal) && checkPasswordUsingBind(principal, password);
    }

    private boolean isSasl() {
        return DIGEST_MD5_METHOD.equals(ldapContextFactory.getAuthentication()) ||
                CRAM_MD5_METHOD.equals(ldapContextFactory.getAuthentication()) ||
                GSSAPI_METHOD.equals(ldapContextFactory.getAuthentication());
    }

    /**
     * Checks password using GSSAPI.
     *
     * @param principal principal
     * @param password  password
     * @return true, if principal can be authenticated with specified password
     */
    private boolean checkPasswordUsingGssapi(String principal, String password) {
        // Use our custom configuration to avoid reliance on external config
        Configuration.setConfiguration(new Krb5LoginConfiguration());
        LoginContext lc;
        try {
            lc = new LoginContext(
                    getClass().getName(),
                    new CallbackHandlerImpl(principal, password)
            );
            lc.login();
        } catch (LoginException e) {
            // Bad username:  Client not found in Kerberos database
            // Bad password:  Integrity check on decrypted field failed
            LdapHelper.LOG.debug("Password is not valid for principal: " + principal, e);
            return false;
        }
        try {
            lc.logout();
        } catch (LoginException e) {
            LdapHelper.LOG.warn("Logout fails", e);
        }
        return true;

    }

    /**
     * Checks password using Bind.
     *
     * @param principal principal
     * @param password  password
     * @return true, if principal can be authenticated with specified password
     */
    private boolean checkPasswordUsingBind(String principal, String password) {
        InitialDirContext ctx = null;
        boolean result;
        try {
            ctx = ldapContextFactory.getInitialDirContext(principal, password);
            ctx.getAttributes("");
            result = true;
        } catch (NamingException e) {
            if (LdapHelper.LOG.isDebugEnabled()) {
                LdapHelper.LOG.debug("Password is not valid for principal: " + principal, e);
            }
            result = false;
        } finally {
            LdapHelper.closeContext(ctx);
        }
        return result;
    }

    private String getPrincipal(String login) throws NamingException {
        if (baseDN == null) {
            throw new IllegalArgumentException("LDAP BaseDN is not set");
        }
        InitialDirContext context = null;
        String principal;
        try {
            if (LdapHelper.LOG.isDebugEnabled()) {
                LdapHelper.LOG.debug("Search principal: " + login);
            }

            context = ldapContextFactory.getInitialDirContext();
            String request = "(&(objectClass=" + userObjectClass + ")(" + loginAttribute + "={0}))";
            if (LdapHelper.LOG.isDebugEnabled()) {
                LdapHelper.LOG.debug("LDAP request: " + request);
            }

            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{});
            controls.setReturningObjFlag(true);
            NamingEnumeration result = context.search(baseDN, request, new String[]{login}, controls);
            String found = null;
            if (result.hasMore()) {
                SearchResult obj = (SearchResult) result.next();
                found = obj.getNameInNamespace();
                if (found != null && result.hasMore()) {
                    found = null;
                    LdapHelper.LOG.error("Login \'" + login + "\' is not unique in LDAP (see attribute " + loginAttribute + ")");
                }
            }

            principal = found;
        } finally {
            LdapHelper.closeContext(context);
        }

        return principal;
    }

    /**
     * Returns login attribute.
     *
     * @return login attribute
     */
    public String getLoginAttribute() {
        return loginAttribute;
    }

    /**
     * Sets login attribute.
     *
     * @param loginAttribute login attribute
     */
    public void setLoginAttribute(String loginAttribute) {
        this.loginAttribute = loginAttribute;
    }

    /**
     * Returns object class of LDAP users.
     *
     * @return object class of LDAP users
     */
    public String getUserObjectClass() {
        return userObjectClass;
    }

    /**
     * Sets object class of LDAP users.
     *
     * @param userObjectClass Object class of LDAP users
     */
    public void setUserObjectClass(String userObjectClass) {
        this.userObjectClass = userObjectClass;
    }

    /**
     * Returns Base DN.
     *
     * @return Base DN
     */
    public String getBaseDN() {
        return baseDN;
    }

    /**
     * Sets Base DN.
     *
     * @param baseDN Base DN
     */
    public void setBaseDN(String baseDN) {
        this.baseDN = baseDN;
    }
}
