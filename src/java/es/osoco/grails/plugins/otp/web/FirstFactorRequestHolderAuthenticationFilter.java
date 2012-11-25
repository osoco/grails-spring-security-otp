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
package es.osoco.grails.plugins.otp.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.groovy.grails.plugins.springsecurity.RequestHolderAuthenticationFilter;
import org.springframework.security.core.Authentication;

/**
 * Extends the Grails Spring Security Core's {@link RequestHolderAuthenticationFilter} to override
 * the <code>successfulAuthentication</code> method in order to avoid the filter sets the
 * <code>Authentication</code> object on the {@link SecurityContextHolder} and invokes to a
 * {@link AuthenticationSuccessHandler}.
 *
 * @author <a href='mailto:rafael.luque@osoco.es'>Rafael Luque</a>
 */
public class FirstFactorRequestHolderAuthenticationFilter extends RequestHolderAuthenticationFilter {

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            Authentication authResult) throws IOException, ServletException {

   	 logger.debug("First authentication success, but now the second-factor authentication is pending.");
    }
}
