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
package es.osoco.grails.plugins.otp.access;

import java.util.Collection;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;

import es.osoco.grails.plugins.otp.authentication.TwoFactorAuthenticationException;
import es.osoco.grails.plugins.otp.authentication.TwoFactorInsufficientAuthenticationException;

/**
 * Uses the affirmative-based logic for roles, i.e. any in the list will grant access, but allows
 * an authenticated voter to 'veto' access. This allows specification of roles and
 * <code>IS_AUTHENTICATED_FULLY</code> on one line in SecurityConfig.groovy.
 *
 * @author <a href='mailto:rafael.luque@osoco.es'>Rafael Luque</a>
 */
public class TwoFactorDecisionManager implements AccessDecisionManager, InitializingBean, MessageSourceAware {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private AccessDecisionManager firstFactorDecisionManager;
	private AccessDecisionVoter twoFactorDecisionVoter;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.AccessDecisionManager#decide(org.springframework.security.core.Authentication, java.lang.Object, java.util.Collection)
	 *
	 * The method can throw the following exceptions to be managed by the {@link ExceptionTranslationFilter}:
	 * <ul>
	 *   <li>AccessDeniedException</li>
	 *   <li>AccessDeniedWithTwoFactorException</li>
	 *   <li>TwoFactorInsufficientAuthenticationException</li>
	 * </ul>
	 */
	public void decide(final Authentication authentication, final Object object, final Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException, InsufficientAuthenticationException {

		try {
			firstFactorDecisionManager.decide(authentication, object, configAttributes);
			checkTwoFactorVoter(authentication, object, configAttributes);
		} catch (AccessDeniedException ae) {
			try {
				checkTwoFactorVoter(authentication, object, configAttributes);
				throw ae;
			} catch (InsufficientAuthenticationException iae) {
				throw new TwoFactorAuthenticationException(messages.getMessage(
					"TwoFactorDecisionManager.twoFactorAuthenticationException",
					"Access is denied and a two-factor authentication will be required"));
			}
		}
	}

	public boolean supports(ConfigAttribute attribute) {
		return firstFactorDecisionManager.supports(attribute) || twoFactorDecisionVoter.supports(attribute);
	}

	/**
	 * Iterates through all <code>AccessDecisionVoter</code>s and ensures each can support the presented class.
	 * <p/>
	 * If one or more voters cannot support the presented class, <code>false</code> is returned.
	 * </p>
	 *
	 * @param clazz the type of secured object being presented
	 * @return true if this type is supported
	 */
	public boolean supports(Class<?> clazz) {
		return firstFactorDecisionManager.supports(clazz) || twoFactorDecisionVoter.supports(clazz);
	}

	/**
	 * Allow the {@link TwoFactorVoter} to veto. If the voter denies,
	 * throw an {@link InsufficientAuthenticationException} exception;
	 * if it grants, returns <code>true</code>;
	 * otherwise returns <code>false</code> if it abstains.
	 */
	private boolean checkTwoFactorVoter(final Authentication authentication, final Object object,
			final Collection<ConfigAttribute> configAttributes) {

		boolean grant = false;
		AccessDecisionVoter voter = getTwoFactorDecisionVoter();
		if (voter != null) {
			int result = voter.vote(authentication, object, configAttributes);
			switch (result) {
				case AccessDecisionVoter.ACCESS_GRANTED:
					grant = true;
					break;
				case AccessDecisionVoter.ACCESS_DENIED:
					twoFactorDeny();
					break;
				default: // abstain
					break;
			}
		}

		return grant;
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(messages, "A message source must be set");
		Assert.notNull(firstFactorDecisionManager, "A first-factor decision manager is required");
		Assert.notNull(twoFactorDecisionVoter, "A two-factor voter is required");
	}

	public void setMessageSource(MessageSource messageSource) {
		messages = new MessageSourceAccessor(messageSource);
	}

	public AccessDecisionManager getFirstFactorDecisionManager() {
		return firstFactorDecisionManager;
	}

	public void setFirstFactorDecisionManager(AccessDecisionManager anAccessDecisionManager) {
		firstFactorDecisionManager = anAccessDecisionManager;
	}

	public AccessDecisionVoter getTwoFactorDecisionVoter() {
		return twoFactorDecisionVoter;
	}

	public void setTwoFactorDecisionVoter(AccessDecisionVoter anAccessDecisionVoter) {
		twoFactorDecisionVoter = anAccessDecisionVoter;
	}

	private void twoFactorDeny() {
		throw new TwoFactorInsufficientAuthenticationException(messages.getMessage(
				"TwoFactorDecisionManager.insufficientAuthentication",
				"Access is denied because of two-factor authentication pending"));
	}
}
