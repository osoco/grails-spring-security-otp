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

import org.springframework.security.authentication.InsufficientAuthenticationException;

/**
 * Thrown if an authentication request is rejected because the credentials are not sufficiently trusted
 * because of the required one-time password is missing.
 *
 * @author <a href="mailto:rafael.luque@osoco.es">Rafael Luque</a>
 */
public class TwoFactorInsufficientAuthenticationException extends InsufficientAuthenticationException {

    private static final long serialVersionUID = 1;

    /**
     * Constructs an <code>InsufficientAuthenticationException</code> with the
     * specified message.
     *
     * @param msg the detail message
     */
    public TwoFactorInsufficientAuthenticationException(String msg) {
        super(msg);
    }

    /**
     * Constructs an <code>InsufficientAuthenticationException</code> with the
     * specified message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public TwoFactorInsufficientAuthenticationException(String msg, Throwable t) {
        super(msg, t);
    }
}
