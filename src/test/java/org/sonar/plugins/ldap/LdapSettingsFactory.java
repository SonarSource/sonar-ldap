package org.sonar.plugins.ldap;


import org.junit.ClassRule;
import org.sonar.api.config.Settings;
import org.sonar.plugins.ldap.server.LdapServer;

public class LdapSettingsFactory {
    public static final String USERS_EXAMPLE_ORG_LDIF = "/users.example.org.ldif";
    public static final String USERS_INFOSUPPORT_COM_LDIF = "/users.infosupport.com.ldif";

    public static final Settings SIMPLEANONYMOUSACCESS;

    static{

        SIMPLEANONYMOUSACCESS = generateSimpleAnonymousAccessSettings();
    }

    private static Settings generateSimpleAnonymousAccessSettings() {
        Settings settings = new Settings();

        settings .setProperty("ldap.url", USERS_EXAMPLE_ORG_LDIF)
                .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org");

        settings.setProperty("ldap1.url", USERS_INFOSUPPORT_COM_LDIF)
                .setProperty("ldap1.user.baseDn", "ou=users,dc=infosupport,dc=com");
        return settings;
    }

    public static Settings generateAuthenticationSettings(LdapServer exampleServer, LdapServer infosupportServer) {
        Settings settings = new Settings();
        settings.setProperty("ldap.url", exampleServer.getUrl())
                .setProperty("ldap.bindDn", "bind")
                .setProperty("ldap.bindPassword", "bindpassword")
                .setProperty("ldap.authentication",  LdapContextFactory.CRAM_MD5_METHOD)
                .setProperty("ldap.realm", "example.org")
                .setProperty("ldap.user.baseDn", "ou=users,dc=example,dc=org");

        settings.setProperty("ldap1.url", infosupportServer.getUrl())
                .setProperty("ldap1.bindDn", "bind")
                .setProperty("ldap1.bindPassword", "bindpassword")
                .setProperty("ldap1.authentication",  LdapContextFactory.CRAM_MD5_METHOD)
                .setProperty("ldap1.realm", "infosupport.com")
                .setProperty("ldap1.user.baseDn", "ou=users,dc=infosupport,dc=com");

        return settings;
    }
}
