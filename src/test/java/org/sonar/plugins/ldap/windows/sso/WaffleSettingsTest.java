/*
 * SonarQube LDAP Plugin
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
package org.sonar.plugins.ldap.windows.sso;

import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.ServletContext;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;

import static org.assertj.core.api.Assertions.assertThat;

public class WaffleSettingsTest {

  private Settings settings;
  private WindowsAuthSettings windowsAuthSettings;
  private ServletContext servletContext;
  private String filterName;

  @Before
  public void init() {
    settings = new Settings();
    windowsAuthSettings = new WindowsAuthSettings(settings);
    servletContext = Mockito.mock(ServletContext.class);
    filterName = "SomeFilterName";
  }

  @Test
  public void defaults() {
    WaffleSettings waffleSettings = new WaffleSettings(filterName, servletContext, windowsAuthSettings);
    validateWaffleSettings(waffleSettings, filterName, servletContext, windowsAuthSettings);
  }

  @Test
  public void nonDefaultSettingsTest() {
    settings.setProperty(WindowsAuthSettings.SONAR_WINDOWS_USER_GROUP_FORMAT, "Negotiate");

    WaffleSettings waffleSettings = new WaffleSettings(filterName, servletContext, windowsAuthSettings);
    validateWaffleSettings(waffleSettings, filterName, servletContext, windowsAuthSettings);
  }

  @Test
  public void getInitParameterNamesTest() {
    WaffleSettings waffleSettings = new WaffleSettings(filterName, servletContext, windowsAuthSettings);
    validateGetInitParameterNames(waffleSettings);
  }

  private static void validateWaffleSettings(WaffleSettings waffleSettings, String expectedFilterName,
    ServletContext expectedServletContext, WindowsAuthSettings windowsAuthSettings) {
    assertThat(waffleSettings.getFilterName()).isEqualTo(expectedFilterName);
    assertThat(waffleSettings.getServletContext()).isEqualTo(expectedServletContext);

    assertThat(waffleSettings.getInitParameter(WaffleSettings.ALLOW_GUEST_LOGIN)).isEqualTo(WaffleSettings.ALLOW_GUEST_LOGIN_VALUE);
    assertThat(waffleSettings.getInitParameter(WaffleSettings.SECURITY_FILTER_PROVIDERS)).isEqualTo(WaffleSettings.SECURITY_FILTER_PROVIDERS_VALUE);
    assertThat(waffleSettings.getInitParameter(WaffleSettings.NEGOTIATE_SECURITY_FILTER_PROVIDER_PROTOCOLS)).isEqualTo(windowsAuthSettings.getProtocols());
  }

  private static void validateGetInitParameterNames(WaffleSettings waffleSettings) {
    Enumeration<String> initParameterNames = waffleSettings.getInitParameterNames();
    Set<String> expectedInitParameterNames = getExpectedInitParameterNames();

    while (initParameterNames.hasMoreElements()) {
      String initParamName = initParameterNames.nextElement();
      assertThat(expectedInitParameterNames.remove(initParamName)).isTrue();
    }

    assertThat(expectedInitParameterNames).isEmpty();
  }

  private static Set<String> getExpectedInitParameterNames() {
    Set<String> expectedInitParameterNames = new HashSet<>();
    expectedInitParameterNames.add(WaffleSettings.ALLOW_GUEST_LOGIN);
    expectedInitParameterNames.add(WaffleSettings.SECURITY_FILTER_PROVIDERS);
    expectedInitParameterNames.add(WaffleSettings.NEGOTIATE_SECURITY_FILTER_PROVIDER_PROTOCOLS);

    return expectedInitParameterNames;
  }
}
