/*
 * SonarQube LDAP Plugin :: Integration Tests
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
package org.sonarsource.ldap.it.utils;

import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.sonar.orchestrator.Orchestrator;
import com.sonar.orchestrator.container.Server;
import com.sonar.orchestrator.locator.FileLocation;
import com.sonar.orchestrator.locator.Location;
import java.io.File;
import javax.annotation.Nullable;
import org.sonar.wsclient.Host;
import org.sonar.wsclient.Sonar;
import org.sonar.wsclient.connectors.ConnectionException;
import org.sonar.wsclient.connectors.HttpClient4Connector;
import org.sonar.wsclient.services.UserPropertyCreateQuery;
import org.sonar.wsclient.services.UserPropertyQuery;
import org.sonarqube.ws.client.HttpConnector;
import org.sonarqube.ws.client.WsClient;
import org.sonarqube.ws.client.WsClientFactories;

import static com.sonar.orchestrator.container.Server.ADMIN_LOGIN;
import static com.sonar.orchestrator.container.Server.ADMIN_PASSWORD;

public class ItUtils {

  public static Location ldapPluginLocation() {
    return FileLocation.byWildcardMavenFilename(new File("../sonar-ldap-plugin/target/"), "sonar-ldap-plugin-*.jar");
  }

  public static String AUTHORIZED = "authorized";
  public static String NOT_AUTHORIZED = "not authorized";

  private ItUtils() {
  }

  public static WsClient newAdminWsClient(Orchestrator orchestrator) {
    return newUserWsClient(orchestrator, ADMIN_LOGIN, ADMIN_PASSWORD);
  }

  public static WsClient newUserWsClient(Orchestrator orchestrator, @Nullable String login, @Nullable String password) {
    Server server = orchestrator.getServer();
    return WsClientFactories.getDefault().newClient(HttpConnector.newBuilder()
      .url(server.getUrl())
      .credentials(login, password)
      .build());
  }

  /**
   * Utility method to check that user can be authorized.
   *
   * @throws IllegalStateException
   */
  public static String loginAttempt(Orchestrator orchestrator, String username, String password) {
    String expectedValue = Long.toString(System.currentTimeMillis());
    Sonar wsClient = createWsClient(orchestrator, username, password);
    try {
      wsClient.create(new UserPropertyCreateQuery("auth", expectedValue));
    } catch (ConnectionException e) {
      return NOT_AUTHORIZED;
    }
    try {
      String value = wsClient.find(new UserPropertyQuery("auth")).getValue();
      if (!Objects.equal(value, expectedValue)) {
        // exceptional case - update+retrieval were successful, but value doesn't match
        throw new IllegalStateException("Expected " + expectedValue + " , but got " + value);
      }
    } catch (ConnectionException e) {
      // exceptional case - update was successful, but not retrieval
      throw new IllegalStateException(e);
    }
    return AUTHORIZED;
  }

  /**
   * Utility method to create {@link org.sonar.wsclient.Sonar} with specified {@code username} and {@code password}.
   * Orchestrator does not provide such method.
   */
  private static Sonar createWsClient(Orchestrator orchestrator, String username, String password) {
    Preconditions.checkNotNull(username);
    Preconditions.checkNotNull(password);
    return new Sonar(new HttpClient4Connector(new Host(orchestrator.getServer().getUrl(), username, password)));
  }
}
