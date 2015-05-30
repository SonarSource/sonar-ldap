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

import com.google.common.base.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.ldap.ldapentryprocessor.FindFirstEntryProcessor;
import org.sonar.plugins.ldap.ldapentryprocessor.LdapEntryProcessor;
import org.sonar.plugins.ldap.ldapentryprocessor.UniqueEntryProcessor;
import org.sonar.plugins.ldap.ldapreferralfilter.AllowAllReferralFilter;
import org.sonar.plugins.ldap.ldapreferralfilter.DenyAllReferralFilter;
import org.sonar.plugins.ldap.ldapreferralfilter.DenyRegExReferralFilter;
import org.sonar.plugins.ldap.ldapreferralfilter.LdapReferralFilter;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.ReferralException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.persistence.NonUniqueResultException;
import java.util.Arrays;

/**
 * Fluent API for building LDAP queries.
 *
 * @author Evgeny Mandrikov
 */
public class LdapSearch
{

    private static final Logger LOG = LoggerFactory.getLogger(LdapSearch.class);

    private final LdapContextFactory contextFactory;

    private String baseDn;
    private int scope = SearchControls.SUBTREE_SCOPE;
    private String request;
    private String[] parameters;
    private String[] returningAttributes;

    public LdapSearch(LdapContextFactory contextFactory)
    {
        this.contextFactory = contextFactory;
    }

    /**
     * Sets BaseDN.
     */
    public LdapSearch setBaseDn(String baseDn)
    {
        this.baseDn = baseDn;
        return this;
    }

    public String getBaseDn()
    {
        return baseDn;
    }

    /**
     * Sets the search scope.
     *
     * @see SearchControls#ONELEVEL_SCOPE
     * @see SearchControls#SUBTREE_SCOPE
     * @see SearchControls#OBJECT_SCOPE
     */
    public LdapSearch setScope(int scope)
    {
        this.scope = scope;
        return this;
    }

    public int getScope()
    {
        return scope;
    }

    /**
     * Sets request.
     */
    public LdapSearch setRequest(String request)
    {
        this.request = request;
        return this;
    }

    public String getRequest()
    {
        return request;
    }

    /**
     * Sets search parameters.
     */
    public LdapSearch setParameters(String... parameters)
    {
        this.parameters = parameters;
        return this;
    }

    public String[] getParameters()
    {
        return parameters;
    }

    /**
     * Sets attributes, which should be returned by search.
     */
    public LdapSearch returns(String... attributes)
    {
        this.returningAttributes = attributes;
        return this;
    }

    public String[] getReturningAttributes()
    {
        return returningAttributes;
    }


    /**
     * @return result, or null if not found
     * @throws NamingException if unable to perform search, or non unique result
     */
    public SearchResult findUnique() throws NamingException
    {
        UniqueEntryProcessor ldapEntryProcessor = new UniqueEntryProcessor();

        iterateSearchResults(ldapEntryProcessor);
        return ldapEntryProcessor.getResult();
    }

    public SearchResult findFirst() throws NamingException
    {

        FindFirstEntryProcessor ldapEntryProcessor = new FindFirstEntryProcessor();

        try
        {
            iterateSearchResults(ldapEntryProcessor);
        }
        catch (NonUniqueResultException e)
        {
            throw new NamingException("Non unique result for " + toString());
        }

        return (SearchResult) ldapEntryProcessor.getResult();
    }

    public void iterateSearchResults(LdapEntryProcessor ldapEntryProcessor) throws NamingException
    {
        LdapReferralFilter ldapReferralFilter = getReferralFilter();
        iterateSearchResults(ldapEntryProcessor, ldapReferralFilter);
    }

    private LdapReferralFilter getReferralFilter()
    {
        LdapReferralHandling referralHandling = contextFactory.getReferralHandling();

        switch (referralHandling)
        {
            case ALLOW_ALL:
                return new AllowAllReferralFilter();
            case DENY_ALL:
                return new DenyAllReferralFilter();
            case FILTERED:
                return new DenyRegExReferralFilter(contextFactory.getReferralFilterList());
            default:
                throw new IllegalStateException("Unknown referralhandling");
        }
    }

    private void iterateSearchResults(LdapEntryProcessor ldapEntryProcessor, LdapReferralFilter ldapReferralFilter) throws NamingException
    {
        LOG.debug("Search: {}", this);
        DirContext context = null;
        boolean threw = false;
        try
        {

            // Create the initial context
            context = contextFactory.createBindContext();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(scope);
            controls.setReturningAttributes(returningAttributes);
            LdapSearchResultContext ldapSearchResultContext = new LdapSearchResultContextImpl(this);


            // Do this in a loop because you don't know how
            // many referrals there will be
            for (boolean moreReferrals = true; moreReferrals; )
            {
                try
                {
                    // Perform the search
                    NamingEnumeration answer = context.search(baseDn, request, parameters, controls);

                    // Print the answer
                    while (answer.hasMore())
                    {
                        ldapEntryProcessor.processLdapSearchResult(ldapSearchResultContext, answer.next());
                        if (ldapSearchResultContext.isIteratingStopped())
                        {
                            return;
                        }
                    }
                    // The search completes with no more referrals
                    moreReferrals = false;

                }
                catch (ReferralException e)
                {
                    if (!ldapReferralFilter.followReferral(e.getReferralInfo()))
                    {
                        moreReferrals = e.skipReferral();
                    }

                    // Point to the new context
                    if (moreReferrals)
                    {
                        context = (DirContext) e.getReferralContext();
                    }
                }
            }

            threw = true;
        }
        finally
        {
            ContextHelper.close(context, threw);
        }
    }

    @Override
    public String toString()
    {
        return Objects.toStringHelper(this)
                .add("baseDn", baseDn)
                .add("scope", scopeToString())
                .add("request", request)
                .add("parameters", Arrays.toString(parameters))
                .add("attributes", Arrays.toString(returningAttributes))
                .toString();
    }

    private String scopeToString()
    {
        switch (scope)
        {
            case SearchControls.ONELEVEL_SCOPE:
                return "onelevel";
            case SearchControls.OBJECT_SCOPE:
                return "object";
            case SearchControls.SUBTREE_SCOPE:
            default:
                return "subtree";
        }
    }

    public SearchResult find(SingleEntryFindMode singleEntryFindMode) throws NamingException
    {
        if(singleEntryFindMode ==SingleEntryFindMode.FIND_FIRST)
            return findFirst();
        else
            return findUnique();
    }
}
