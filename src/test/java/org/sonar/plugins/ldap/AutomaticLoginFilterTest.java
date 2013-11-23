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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.sonar.api.security.ExternalUsersProvider.Context;
import org.sonar.api.security.UserDetails;
import org.sonar.api.utils.SonarException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


public class AutomaticLoginFilterTest {
  
  private PreAuthHelper preAuthHelper;
  private LdapRealm ldapRealm;
  private HttpServletRequest request;
  private HttpServletResponse response;
  private FilterChain filterChain;
  private AutomaticLoginFilter filter;
  private static String USERNAME = "testuser";
  
  @Before
  public void setUp() {
    preAuthHelper = mock(PreAuthHelper.class);
    ldapRealm = mock(LdapRealm.class, Mockito.RETURNS_DEEP_STUBS);
    filterChain = mock(FilterChain.class);
    request = mock(HttpServletRequest.class);
    response = mock(HttpServletResponse.class);
    filter = new AutomaticLoginFilter(preAuthHelper, ldapRealm);
  }

  @Test
  public void testDoFilterNoPreAuth() throws IOException, ServletException {
    when(preAuthHelper.isPreAuthRequired(request)).thenReturn(false);
    
    filter.doFilter(request, response, filterChain);
    
    assertUserNotFound();
  }
  
  @Test
  public void testDoFilterBlankUser() throws IOException, ServletException {
    when(preAuthHelper.isPreAuthRequired(request)).thenReturn(true);
    when(preAuthHelper.findPreAuthenticatedUser(request)).thenReturn("");
    
    filter.doFilter(request, response, filterChain);
    
    assertUserNotFound();
  }
  
  @Test
  public void testDoFilterUserNotInLdapException() throws IOException, ServletException {
    when(preAuthHelper.isPreAuthRequired(request)).thenReturn(true);
    when(preAuthHelper.findPreAuthenticatedUser(request)).thenReturn(USERNAME);
    when(ldapRealm.getUsersProvider()).thenThrow(new SonarException("User not in LDAP"));
    
    filter.doFilter(request, response, filterChain);
    
    assertUserNotFound();
  }
  
  @Test
  public void testDoFilterUserNotInLdap() throws IOException, ServletException {
    when(preAuthHelper.isPreAuthRequired(request)).thenReturn(true);
    when(preAuthHelper.findPreAuthenticatedUser(request)).thenReturn(USERNAME);
    when(ldapRealm.getUsersProvider().doGetUserDetails(Matchers.any(Context.class))).thenReturn(null);
    
    filter.doFilter(request, response, filterChain);
    
    assertUserNotFound();
  }
  
  @Test
  public void testDoFilterUserFound() throws IOException, ServletException {
    when(preAuthHelper.isPreAuthRequired(request)).thenReturn(true);
    when(preAuthHelper.findPreAuthenticatedUser(request)).thenReturn(USERNAME);
    UserDetails userDetails = new UserDetails();
    userDetails.setName(USERNAME);
    when(ldapRealm.getUsersProvider().doGetUserDetails(Matchers.any(Context.class))).thenReturn(userDetails);
    
    filter.doFilter(request, response, filterChain);
    
    assertUserFound();
  }

  private void assertUserFound() throws IOException {
    verify(response).sendRedirect(Matchers.anyString());
  }

  private void assertUserNotFound() throws IOException, ServletException {
    verify(filterChain).doFilter(request, response);
  }
}
