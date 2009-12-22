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
