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
    @Override
    public String getKey() {
        return "ldap";
    }

    @Override
    public String getName() {
        return "Ldap";
    }

    @Override
    public String getDescription() {
        return "Plugs authentication mechanism to a LDAP directory to delegate passwords management.";
    }

    @Override
    public List<Class<? extends Extension>> getExtensions() {
        ArrayList<Class<? extends Extension>> extensions = new ArrayList<Class<? extends Extension>>();
        extensions.add(LdapAuthenticator.class);
        extensions.add(LdapConfiguration.class);
        return extensions;
    }
}