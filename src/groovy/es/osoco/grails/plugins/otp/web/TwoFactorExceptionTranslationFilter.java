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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.Assert;

import es.osoco.grails.plugins.otp.authentication.TwoFactorAuthenticationException;
import es.osoco.grails.plugins.otp.authentication.TwoFactorInsufficientAuthenticationException;

/**
 * Handles any <code>AccessDeniedException</code>, <code>TwoFactorAuthenticationException</code> and
 * <code>TwoFactorInsufficientAuthenticationException</code> thrown within the filter chain.
 *
 * @author <a href="mailto:rafael.luque@osoco.es">Rafael Luque</a>
 */
public class TwoFactorExceptionTranslationFilter extends ExceptionTranslationFilter {

	private AuthenticationEntryPoint secondFactorAuthenticationEntryPoint;
	private AuthenticationEntryPoint twoFactorsAuthenticationEntryPoint;
	private boolean useTwoFactorsCombinedLoginForm;
	private RequestCache requestCache;

	@Override
	protected void sendStartAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			AuthenticationException reason) throws ServletException, IOException {
		// SEC-112: Clear the SecurityContextHolder's Authentication, as the
		// existing Authentication is no longer considered valid
		SecurityContextHolder.getContext().setAuthentication(null);
		requestCache.saveRequest(request, response);
		AuthenticationEntryPoint entryPoint = entryPointByReason(reason);
		if (logger.isDebugEnabled()) {
			logger.debug("Commence authentication using [" + entryPoint.getClass().getName() + " authentication entry point");
		}
		entryPoint.commence(request, response, reason);
	}

	protected AuthenticationEntryPoint entryPointByReason(AuthenticationException reason) {
		if (useTwoFactorsCombinedLoginForm && (reason instanceof TwoFactorAuthenticationException)) {
			return twoFactorsAuthenticationEntryPoint;
		}

		return reason instanceof TwoFactorInsufficientAuthenticationException ?
				secondFactorAuthenticationEntryPoint :
				getAuthenticationEntryPoint();
	}

	public void setSecondFactorAuthenticationEntryPoint(AuthenticationEntryPoint secondFactorAuthenticationEntryPoint) {
		this.secondFactorAuthenticationEntryPoint = secondFactorAuthenticationEntryPoint;
	}

	public void setTwoFactorsAuthenticationEntryPoint(AuthenticationEntryPoint twoFactorsAuthenticationEntryPoint) {
		this.twoFactorsAuthenticationEntryPoint = twoFactorsAuthenticationEntryPoint;
	}

	public void setUseTwoFactorsCombinedLoginForm(boolean useTwoFactorsCombinedLoginForm) {
		this.useTwoFactorsCombinedLoginForm = useTwoFactorsCombinedLoginForm;
	}

	@Override
	public void setRequestCache(RequestCache requestCache) {
		super.setRequestCache(requestCache);
		this.requestCache = requestCache;
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(secondFactorAuthenticationEntryPoint, "secondFactorAuthenticationEntryPoint must be specified");
		Assert.notNull(useTwoFactorsCombinedLoginForm, "useTwoFactorsCombinedLoginForm must be specified");
	}
}
