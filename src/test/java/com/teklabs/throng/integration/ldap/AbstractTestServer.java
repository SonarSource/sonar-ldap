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

/**
 * @author Evgeny Mandrikov
 */
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
