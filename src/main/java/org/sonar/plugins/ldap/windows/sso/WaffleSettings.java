/*
 * SonarQube LDAP Plugin
 * Copyright (C) 2009 SonarSource
 * sonarqube@googlegroups.com
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
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import org.sonar.api.utils.log.Loggers;
import org.sonar.plugins.ldap.windows.auth.WindowsAuthSettings;
import waffle.servlet.spi.NegotiateSecurityFilterProvider;

public class WaffleSettings implements FilterConfig {
  public static final String ALLOW_GUEST_LOGIN = "allowGuestLogin";
  public static final String ALLOW_GUEST_LOGIN_VALUE = "false";

  public static final String SECURITY_FILTER_PROVIDERS = "securityFilterProviders";
  public static final String SECURITY_FILTER_PROVIDERS_VALUE = NegotiateSecurityFilterProvider.class.getName();

  public static final String NEGOTIATE_SECURITY_FILTER_PROVIDER_PROTOCOLS = NegotiateSecurityFilterProvider.class.getName()
          + "/protocols";

  private final ServletContext servletContext;
  private final String filterName;
  private Map<String, String> initParams;

  public WaffleSettings(String filterName, ServletContext servletContext, WindowsAuthSettings windowsAuthSettings) {
    this.filterName = filterName;
    this.servletContext = servletContext;

    initParams = new HashMap<>();
    // allowGuestLogin is enabled by default. Explicitly disabling the guest login.
    initParams.put(ALLOW_GUEST_LOGIN, ALLOW_GUEST_LOGIN_VALUE);
    initParams.put(SECURITY_FILTER_PROVIDERS, SECURITY_FILTER_PROVIDERS_VALUE);
    initParams.put(NEGOTIATE_SECURITY_FILTER_PROVIDER_PROTOCOLS, windowsAuthSettings.getProtocols());

    Loggers.get(getClass()).debug("Waffle initialization parameters : {}", initParams);
  }

  @Override
  public String getFilterName() {
    return filterName;
  }

  @Override
  public ServletContext getServletContext() {
    return servletContext;
  }

  @Override
  public String getInitParameter(String s) {
    return initParams.get(s);
  }

  @Override
  public Enumeration<String> getInitParameterNames() {
    return new Vector<>(initParams.keySet()).elements();
  }
}
