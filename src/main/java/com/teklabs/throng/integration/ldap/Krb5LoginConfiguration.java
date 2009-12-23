package com.teklabs.throng.integration.ldap;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.HashMap;

/**
 * @author Evgeny Mandrikov
 */
public class Krb5LoginConfiguration extends Configuration {
    private static AppConfigurationEntry[] configList = new AppConfigurationEntry[1];

    /**
     * Creates a new instance of Krb5LoginConfiguration.
     */
    public Krb5LoginConfiguration() {
        super();
        String loginModule = "com.sun.security.auth.module.Krb5LoginModule";
        AppConfigurationEntry.LoginModuleControlFlag flag = AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;
        configList[0] = new AppConfigurationEntry(loginModule, flag, new HashMap<String, Object>());
    }

    /**
     * Interface method requiring us to return all the LoginModules we know about.
     */
    public AppConfigurationEntry[] getAppConfigurationEntry(String applicationName) {
        // We will ignore the applicationName, since we want all apps to use Kerberos V5
        return configList;
    }

    /**
     * Interface method for reloading the configuration.  We don't need this.
     */
    public void refresh() {
        // Right now this is a load once scheme and we will not implement the refresh method
    }
}
