package org.sonar.plugins.ldap;

import org.sonar.api.Extension;
import org.sonar.api.Plugin;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Evgeny Mandrikov
 */
@SuppressWarnings({"UnusedDeclaration"})
public class LdapPlugin implements Plugin {
    public String getKey() {
        return "ldap";
    }

    public String getName() {
        return "Ldap";
    }

    public String getDescription() {
        return "Plugs authentication mechanism to a LDAP directory to delegate passwords management.";
    }

    public List<Class<? extends Extension>> getExtensions() {
        List<Class<? extends Extension>> extensions = new ArrayList<Class<? extends Extension>>();
        extensions.add(LdapAuthenticator.class);
        extensions.add(LdapConfiguration.class);
        return extensions;
    }
}