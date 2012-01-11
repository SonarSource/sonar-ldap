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

package com.teklabs.throng.integration.ldap;

/**
 * @author Evgeny Mandrikov
 */
@Deprecated
public abstract class AbstractTestServer {
  private String serverRoot = null;

  private String id = "test";

  private String realm = "example.org";

  private String baseDN = "dc=example,dc=org";

  public final String getServerRoot() {
    return serverRoot;
  }

  public final void setServerRoot(String serverRoot) {
    this.serverRoot = serverRoot;
  }

  public String getId() {
    return id;
  }

  public final String getRealm() {
    return realm;
  }

  public final String getBaseDN() {
    return baseDN;
  }

  /**
   * Start the server.
   *
   * @throws Exception if something wrong
   */

  public abstract void start() throws Exception;

  /**
   * Shut down the server.
   *
   * @throws Exception if something wrong
   */
  public abstract void stop() throws Exception;

  public abstract void initialize(String ldifFile) throws Exception;
}
