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
