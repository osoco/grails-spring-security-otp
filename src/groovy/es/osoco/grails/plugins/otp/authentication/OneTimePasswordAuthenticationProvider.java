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

import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

import es.osoco.grails.plugins.otp.OneTimePasswordService;
import es.osoco.grails.plugins.otp.userdetails.GrailsOtpUser;

/**
 * A subclass of {@link DaoAuthenticationProvider} that supports the {@link OneTimePasswordAuthenticationToken}
 * kind of token and checks the OTP validity delegating to the {@link OneTimePasswordService} as an additional
 * check.
 *
 * @author <a href="mailto:rafael.luque@osoco.es">Rafael Luque</a>
 */
public class OneTimePasswordAuthenticationProvider extends DaoAuthenticationProvider {

	private OneTimePasswordService oneTimePasswordService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		Assert.isInstanceOf(OneTimePasswordAuthenticationToken.class, authentication,
			messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
				"Only OneTimePasswordAuthenticationToken is supported"));

		// Determine username
		String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();

		boolean cacheWasUsed = true;
		UserDetails user = getUserCache().getUserFromCache(username);

		if (user == null) {
			cacheWasUsed = false;

			try {
				user = retrieveUser(username, (OneTimePasswordAuthenticationToken) authentication);
			} catch (UsernameNotFoundException notFound) {

				if (hideUserNotFoundExceptions) {
					throw new BadCredentialsException(messages.getMessage(
							"AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
				}
				throw notFound;
			}

			Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
		}

		try {
			getPreAuthenticationChecks().check(user);
			additionalAuthenticationChecks(user, (OneTimePasswordAuthenticationToken) authentication);
		} catch (AuthenticationException exception) {
			if (cacheWasUsed) {
				// There was a problem, so try again after checking
				// we're using latest data (i.e. not from the cache)
				cacheWasUsed = false;
				user = retrieveUser(username, (OneTimePasswordAuthenticationToken) authentication);
				getPreAuthenticationChecks().check(user);
				additionalAuthenticationChecks(user, (OneTimePasswordAuthenticationToken) authentication);
			} else {
				throw exception;
			}
		}

		getPostAuthenticationChecks().check(user);

		if (!cacheWasUsed) {
			getUserCache().putUserInCache(user);
		}

		Object principalToReturn = user;

		if (isForcePrincipalAsString()) {
			principalToReturn = user.getUsername();
		}

		return createSuccessAuthentication(principalToReturn, authentication, user);
	}

	protected final UserDetails retrieveUser(String username, OneTimePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		UserDetails loadedUser;

		try {
			loadedUser = getUserDetailsService().loadUserByUsername(username);
		}
		catch (DataAccessException repositoryProblem) {
			throw new AuthenticationServiceException(repositoryProblem.getMessage(), repositoryProblem);
		}

		if (loadedUser == null) {
			throw new AuthenticationServiceException(
					"UserDetailsService returned null, which is an interface contract violation");
		}
		return loadedUser;
	}

	@SuppressWarnings("deprecation")
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			OneTimePasswordAuthenticationToken authentication) throws AuthenticationException {

		if (logger.isDebugEnabled()) {
			logger.debug("OneTimePasswordAuthenticationProvider for authentication " + authentication.getClass().getName());
		}

		if (authentication.getCredentials() == null) {
			logger.debug("Authentication failed: no credentials provided");

			throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"),
					isIncludeDetailsObject() ? userDetails : null);
		}

		String presentedPassword = authentication.getCredentials().toString();

		if (!oneTimePasswordService.isPasswordValid(presentedPassword, ((GrailsOtpUser)userDetails).getSecretKey())) {
			logger.debug("Authentication failed: one time password is not valid");

			throw new BadCredentialsException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"),
					isIncludeDetailsObject() ? userDetails : null);
		}
	}

	@Override
	public boolean supports(Class<? extends Object> authentication) {
		boolean supported = OneTimePasswordAuthenticationToken.class.isAssignableFrom(authentication);
		if (logger.isDebugEnabled()) {
			logger.debug("Supports " + authentication.getClass().getName() + " ?  " + supported);
		}
		return supported;
	}

	public void setOneTimePasswordService(OneTimePasswordService oneTimePasswordService) {
		this.oneTimePasswordService = oneTimePasswordService;
	}
}
