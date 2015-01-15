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
package org.sonar.plugins.ldap.ldapreferralfilter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class DenyRegExReferralFilter implements LdapReferralFilter
{
    private static final Logger LOG = LoggerFactory.getLogger(DenyRegExReferralFilter.class);
    List<String> deniedReferrals;

    public DenyRegExReferralFilter(List<String> deniedReferrals)
    {
        this.deniedReferrals = deniedReferrals;
    }

    @Override
    public boolean followReferral(Object referralInfo)
    {
        for (String deniedReferral : deniedReferrals)
        {
            if (referralInfo.toString().matches(deniedReferral))
            {
                LOG.debug("ignoring referral " + referralInfo + " because of regex " + deniedReferral);
                return false;
            }
        }
        LOG.debug("following referral" + referralInfo);
        return true;
    }
}
