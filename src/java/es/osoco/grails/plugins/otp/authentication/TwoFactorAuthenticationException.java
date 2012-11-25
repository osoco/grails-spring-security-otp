/*
 * ====================================================================
 *    ____  _________  _________
 *   / __ \/ ___/ __ \/ ___/ __ \
 *  / /_/ (__  ) /_/ / /__/ /_/ /
 *  \____/____/\____/\___/\____/
 *
 *  ~ La empresa de los programadores profesionales ~
 *
 *  | http://osoco.es
 *  |
 *  | Edificio Moma Lofts
 *  | Planta 3, Loft 18
 *  | Ctra. Mostoles-Villaviciosa, Km 0,2
 *  | Mostoles, Madrid 28935 Spain
 *
 * ====================================================================
 *
 * Copyright 2012 OSOCO. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package es.osoco.grails.plugins.otp.authentication;

import org.springframework.security.core.AuthenticationException;

/**
 * Thrown if an {@link org.springframework.security.core.Authentication Authentication} object does not hold
 * a required authority and the secured object requires also one-time password authentication.
 *
 * @author <a href="mailto:rafael.luque@osoco.es">Rafael Luque</a>
 */
public class TwoFactorAuthenticationException extends AuthenticationException {

    private static final long serialVersionUID = 1;

	/**
     * Constructs an <code>TwoFactorAuthenticationException</code> with the specified
     * message.
     *
     * @param msg the detail message
     */
    public TwoFactorAuthenticationException(String msg) {
        super(msg);
    }

    /**
     * Constructs an <code>TwoFactorAuthenticationException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public TwoFactorAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }
}
