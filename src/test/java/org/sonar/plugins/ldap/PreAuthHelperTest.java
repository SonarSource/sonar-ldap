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

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.sonar.api.config.Settings;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class PreAuthHelperTest {
  
  private PreAuthHelper preAuthHelper;
  private Settings settings;
  
  @Before
  public void setUp() {
    this.settings = new Settings();
  }
  
  @Test
  public void testIsNotPreAuth() {
    settings.setProperty(PreAuthHelper.LDAP_PREAUTHENTICATION_KEY, false);
    this.preAuthHelper = new PreAuthHelper(settings);
    
    boolean preAuth = preAuthHelper.isPreAuth();
    
    assertThat(preAuth).isEqualTo(false);
  }

  @Test
  public void testIsPreAuth() {
    settings.setProperty(PreAuthHelper.LDAP_PREAUTHENTICATION_KEY, true);
    this.preAuthHelper = new PreAuthHelper(settings);
    
    boolean preAuth = preAuthHelper.isPreAuth();
    
    assertThat(preAuth).isEqualTo(true);
  }

  @Test
  public void testFindPreAuthenticatedDefaultUser() {
    this.preAuthHelper = new PreAuthHelper(settings);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader(PreAuthHelper.DEFAULT_PRE_AUTH_HEADER_NAME)).thenReturn("test");
    
    String user = preAuthHelper.findPreAuthenticatedUser(request);
    
    assertThat(user).isEqualTo("test");
  }
  
  @Test
  public void testFindPreAuthenticatedCustomUser() {
    String headerName = "my_header";
    settings.setProperty(PreAuthHelper.LDAP_PRE_AUTH_HEADER_NAME_KEY, headerName);
    this.preAuthHelper = new PreAuthHelper(settings);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getHeader(headerName)).thenReturn("test");
    
    String user = preAuthHelper.findPreAuthenticatedUser(request);
    
    assertThat(user).isEqualTo("test");
  }

}
