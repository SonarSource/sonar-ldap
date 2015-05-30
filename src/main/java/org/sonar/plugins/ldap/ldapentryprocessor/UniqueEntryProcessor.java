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
package org.sonar.plugins.ldap.ldapentryprocessor;

import org.sonar.plugins.ldap.LdapSearchResultContext;

import javax.naming.NamingException;
import javax.naming.directory.SearchResult;

public class UniqueEntryProcessor implements LdapEntryProcessor
{
    private SearchResult result = null;
    private int count = 0;

    @Override
    public void processLdapSearchResult(LdapSearchResultContext ldapSearchResultContext, Object next) throws NamingException
    {
        count++;
        result = (SearchResult) next;

        if (count > 1)
        {
            throw new NamingException("Non unique result for " + ldapSearchResultContext.getLdapSearch().toString());
        }
    }

    public SearchResult getResult()
    {
        return result;
    }
}
