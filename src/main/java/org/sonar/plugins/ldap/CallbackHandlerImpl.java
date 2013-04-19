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

package org.sonar.plugins.ldap;

import javax.security.auth.callback.*;
import java.io.IOException;

/**
 * @author Evgeny Mandrikov
 */
public class CallbackHandlerImpl implements CallbackHandler {
    private String name;
    private String password;

    public CallbackHandlerImpl(String name, String password) {
        this.name = name;
        this.password = password;
    }

    public void handle(Callback[] callbacks) throws UnsupportedCallbackException, IOException {
        for (Callback callBack : callbacks) {
            if (callBack instanceof NameCallback) {
                // Handles username callback
                NameCallback nameCallback = (NameCallback) callBack;
                nameCallback.setName(name);
            } else if (callBack instanceof PasswordCallback) {
                // Handles password callback
                PasswordCallback passwordCallback = (PasswordCallback) callBack;
                passwordCallback.setPassword(password.toCharArray());
            } else {
                throw new UnsupportedCallbackException(callBack, "Callback not supported");
            }
        }
    }
}
