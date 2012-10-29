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
package es.osoco.grails.plugins.otp.web

import es.osoco.grails.plugins.otp.authentication.TwoFactorAuthenticationException
import es.osoco.grails.plugins.otp.authentication.TwoFactorInsufficientAuthenticationException

import org.springframework.security.web.access.ExceptionTranslationFilter

import java.io.IOException

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.util.ThrowableAnalyzer
import org.springframework.security.web.util.ThrowableCauseExtractor
import org.springframework.util.Assert
import org.springframework.web.filter.GenericFilterBean

/**
 * Handles any <code>AccessDeniedException</code>, <code>TwoFactorAuthenticationException</code> and 
 * <code>TwoFactorInsufficientAuthenticationException</code> thrown within the filter chain.
 *
 * @author <a href="mailto:rafael.luque@osoco.es">Rafael Luque</a>
 */
class TwoFactorExceptionTranslationFilter extends ExceptionTranslationFilter {

    AuthenticationEntryPoint secondFactorAuthenticationEntryPoint
    AuthenticationEntryPoint twoFactorsAuthenticationEntryPoint
    boolean useTwoFactorsCombinedLoginForm

    RequestCache requestCache = new HttpSessionRequestCache()

    @Override
    public void afterPropertiesSet() {
        super.afterPropertiesSet()
        Assert.notNull(secondFactorAuthenticationEntryPoint, "secondFactorAuthenticationEntryPoint must be specified")
        Assert.notNull(useTwoFactorsCombinedLoginForm, "useTwoFactorsCombinedLoginForm must be specified")
    }

    @Override
    protected void sendStartAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            AuthenticationException reason) throws ServletException, IOException {
        // SEC-112: Clear the SecurityContextHolder's Authentication, as the
        // existing Authentication is no longer considered valid
        SecurityContextHolder.getContext().setAuthentication(null)
        requestCache.saveRequest(request, response)
        def entryPoint = entryPointByReason(reason)
        logger.debug("Commence authentication using [${entryPoint.class.name}] authentication entry point")
        entryPoint.commence(request, response, reason)
    }

    protected AuthenticationEntryPoint entryPointByReason(AuthenticationException reason) {
        def entryPoint

        if (useTwoFactorsCombinedLoginForm && (reason instanceof TwoFactorAuthenticationException)) {
            entryPoint = twoFactorsAuthenticationEntryPoint
        } else {
            entryPoint = reason instanceof TwoFactorInsufficientAuthenticationException ? 
                secondFactorAuthenticationEntryPoint :
                authenticationEntryPoint
        }
        entryPoint

    }

}

