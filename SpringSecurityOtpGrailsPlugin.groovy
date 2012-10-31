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
import es.osoco.grails.plugins.otp.OneTimePasswordService

import es.osoco.grails.plugins.otp.access.AnnotationMultipleVoterFilterInvocationDefinition
import es.osoco.grails.plugins.otp.access.InterceptUrlMapMultipleVoterFilterInvocationDefinition
import es.osoco.grails.plugins.otp.access.OneTimePasswordVoter
import es.osoco.grails.plugins.otp.access.RequestmapMultipleVoterFilterInvocationDefinition
import es.osoco.grails.plugins.otp.access.TwoFactorDecisionManager

import es.osoco.grails.plugins.otp.authentication.NopAuthenticationSuccessHandler
import es.osoco.grails.plugins.otp.authentication.OneTimePasswordAuthenticationProvider

import es.osoco.grails.plugins.otp.userdetails.OneTimePasswordUserDetailsService

import es.osoco.grails.plugins.otp.web.FirstFactorRequestHolderAuthenticationFilter
import es.osoco.grails.plugins.otp.web.OneTimePasswordAuthenticationFilter
import es.osoco.grails.plugins.otp.web.TwoFactorExceptionTranslationFilter

import org.codehaus.groovy.grails.plugins.springsecurity.AjaxAwareAuthenticationEntryPoint
import org.codehaus.groovy.grails.plugins.springsecurity.AjaxAwareAuthenticationSuccessHandler
import org.codehaus.groovy.grails.plugins.springsecurity.RequestHolderAuthenticationFilter
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.util.AntUrlPathMatcher
import org.springframework.security.web.util.RegexUrlPathMatcher

class SpringSecurityOtpGrailsPlugin {

	def version = "0.1"
	def grailsVersion = "1.3.7 > *"
	def loadAfter = ['springSecurityCore']
	def title = "Spring Security OTP Plugin"
	def authorEmail = "info@osoco.es"
	def organization = [name: "OSOCO", url: "http://osoco.es/"]
	def developers = [
		[ name: "Rafael Luque", email: "rafael.luque@osoco.es" ],
		[ name: "Arturo Garcia", email: "arturo.garcia@osoco.es" ] ]
	def description = 'Adds support for one-time password to Spring Security'

	def license = "APACHE"
	def documentation = "http://grails.org/plugin/spring-security-otp"
	def scm = [ url: "https://github.com/osoco/grails-spring-security-otp" ]
	def issueManagement = [ system: "GitHub", url: "https://github.com/osoco/grails-spring-security-otp/issues" ]

	def doWithSpring = {

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		SpringSecurityUtils.loadSecondaryConfig 'DefaultOtpSecurityConfig'

		conf = SpringSecurityUtils.securityConfig
		if (!conf.otp.active) {
			return
		}

		println 'Configuring Spring Security OTP...'

		/** otpAuthenticationFilter */
		otpAuthenticationFilter(OneTimePasswordAuthenticationFilter) {
			authenticationManager = ref('authenticationManager')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
			authenticationSuccessHandler = ref('authenticationSuccessHandler')
			authenticationFailureHandler = ref('authenticationFailureHandler')
			rememberMeServices = ref('rememberMeServices')
			authenticationDetailsSource = ref('authenticationDetailsSource')
			filterProcessesUrl = conf.otp.apf.filterProcessesUrl // '/j_spring_security_otp'
			usernameParameter = conf.otp.apf.usernameParameter // 'j_username'
			passwordParameter = conf.otp.apf.otpParameter // 'j_otp'
			continueChainBeforeSuccessfulAuthentication = conf.otp.apf.continueChainBeforeSuccessfulAuthentication
			allowSessionCreation = conf.otp.apf.allowSessionCreation
			postOnly = conf.otp.apf.postOnly
		}

		/** otpAuthenticationProvider */
		otpAuthenticationProvider(OneTimePasswordAuthenticationProvider) {
			userDetailsService = ref('otpUserDetailsService')
			oneTimePasswordService = ref('oneTimePasswordService')
			passwordEncoder = null
			userCache = ref('userCache')
			saltSource = null
			preAuthenticationChecks = ref('preAuthenticationChecks')
			postAuthenticationChecks = ref('postAuthenticationChecks')
			hideUserNotFoundExceptions = conf.dao.hideUserNotFoundExceptions // true
		}

		/** oneTimePasswordService */
		oneTimePasswordService(OneTimePasswordService) {
			otpDigits = conf.otp.totp.digits
			otpAlgorithm = conf.otp.totp.algorithm
			preStepsWindow = conf.otp.totp.preStepsValidWindow
			postStepsWindow = conf.otp.totp.postStepsValidWindow
		}

		/** userDetailsService */
		otpUserDetailsService(OneTimePasswordUserDetailsService) {
			grailsApplication = ref('grailsApplication')
		}

		/** otpAuthenticationEntryPoint */
		otpAuthenticationEntryPoint(AjaxAwareAuthenticationEntryPoint) {
			loginFormUrl = conf.otp.auth.loginFormUrl // '/login/authOTP'
			forceHttps = conf.otp.auth.forceHttps // false
			ajaxLoginFormUrl = conf.otp.auth.ajaxLoginFormUrl // '/login/authOTPAjax'
			useForward = conf.otp.auth.useForward // false
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
		}

		if (conf.otp.useTwoFactorsCombinedLoginForm) {

			/** twoFactorsAuthenticationEntryPoint */
			twoFactorsAuthenticationEntryPoint(AjaxAwareAuthenticationEntryPoint) {
				loginFormUrl = conf.otp.auth.combinedLoginFormUrl // '/login/authTwoFactors'
				forceHttps = conf.otp.auth.forceHttps // false
				ajaxLoginFormUrl = conf.otp.auth.combinedAjaxLoginFormUrl // '/login/authTwoFactorsAjax'
				useForward = conf.otp.auth.useForward // false
				portMapper = ref('portMapper')
				portResolver = ref('portResolver')
			}

			/** twoFactorExceptionTranslationFilter */
			twoFactorExceptionTranslationFilter(TwoFactorExceptionTranslationFilter) {
				useTwoFactorsCombinedLoginForm = conf.otp.useTwoFactorsCombinedLoginForm
				authenticationEntryPoint = ref('authenticationEntryPoint')
				secondFactorAuthenticationEntryPoint = ref('otpAuthenticationEntryPoint')
				twoFactorsAuthenticationEntryPoint = ref('twoFactorsAuthenticationEntryPoint')
				accessDeniedHandler = ref('accessDeniedHandler')
				authenticationTrustResolver = ref('authenticationTrustResolver')
				requestCache = ref('requestCache')
			}

			/** nonRedirectAuthenticationSuccessHandler */
			nopAuthenticationSuccessHandler(NopAuthenticationSuccessHandler)

			/** firstFactorAuthenticationFilter */
			firstFactorAuthenticationFilter(FirstFactorRequestHolderAuthenticationFilter) {
				authenticationManager = ref('authenticationManager')
				sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
				authenticationSuccessHandler = ref('nopAuthenticationSuccessHandler')
				authenticationFailureHandler = ref('authenticationFailureHandler')
				rememberMeServices = ref('rememberMeServices')
				authenticationDetailsSource = ref('authenticationDetailsSource')
				filterProcessesUrl = conf.otp.apf.twoFactorsFilterProcessesUrl // '/j_spring_security_twofactors'
				usernameParameter = conf.otp.apf.usernameParameter // 'j_username'
				passwordParameter = conf.otp.apf.passwordParameter // 'j_password'
				continueChainBeforeSuccessfulAuthentication = true
				allowSessionCreation = conf.otp.apf.allowSessionCreation
				postOnly = conf.otp.apf.postOnly
			}

			/** secondFactorAuthenticationFilter */
			secondFactorAuthenticationFilter(OneTimePasswordAuthenticationFilter) {
				authenticationManager = ref('authenticationManager')
				sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
				authenticationSuccessHandler = ref('authenticationSuccessHandler')
				authenticationFailureHandler = ref('authenticationFailureHandler')
				rememberMeServices = ref('rememberMeServices')
				authenticationDetailsSource = ref('authenticationDetailsSource')
				filterProcessesUrl = conf.otp.apf.twoFactorsFilterProcessesUrl // '/j_spring_security_twofactors'
				usernameParameter = conf.otp.apf.usernameParameter // 'j_username'
				passwordParameter = conf.otp.apf.otpParameter // 'j_otp'
				continueChainBeforeSuccessfulAuthentication = conf.otp.apf.continueChainBeforeSuccessfulAuthentication
				allowSessionCreation = conf.otp.apf.allowSessionCreation
				postOnly = conf.otp.apf.postOnly
			}

			SpringSecurityUtils.registerFilter 'firstFactorAuthenticationFilter', SecurityFilterPosition.FORM_LOGIN_FILTER.order + 1
			SpringSecurityUtils.registerFilter 'secondFactorAuthenticationFilter', SecurityFilterPosition.FORM_LOGIN_FILTER.order + 2

		} else {

			/** twoFactorExceptionTranslationFilter */
			twoFactorExceptionTranslationFilter(TwoFactorExceptionTranslationFilter) {
				useTwoFactorsCombinedLoginForm = conf.otp.useTwoFactorsCombinedLoginForm
				authenticationEntryPoint = ref('authenticationEntryPoint')
				secondFactorAuthenticationEntryPoint = ref('otpAuthenticationEntryPoint')
				accessDeniedHandler = ref('accessDeniedHandler')
				authenticationTrustResolver = ref('authenticationTrustResolver')
				requestCache = ref('requestCache')
			}
		}

		/** otpVoter **/
		otpVoter(OneTimePasswordVoter)
		SpringSecurityUtils.registerVoter 'otpVoter'

		/** twoFactorAccessDecisionManager */
		twoFactorDecisionManager(TwoFactorDecisionManager) {
			firstFactorDecisionManager = ref('accessDecisionManager')
			twoFactorDecisionVoter = ref('otpVoter')
		}

		/** filterInvocationInterceptor */
		filterInvocationInterceptor(FilterSecurityInterceptor) {
			authenticationManager = ref('authenticationManager')
			accessDecisionManager = ref('twoFactorDecisionManager')
			securityMetadataSource = ref('objectDefinitionSource')
			runAsManager = ref('runAsManager')
		}

		def createRefList = { names -> names.collect { name -> ref(name) } }
		def decisionVoters = createRefList(SpringSecurityUtils.getVoterNames())
		String securityConfigType = SpringSecurityUtils.securityConfigType

		if (securityConfigType == 'Annotation') {
			objectDefinitionSource(AnnotationMultipleVoterFilterInvocationDefinition) {
				application = ref('grailsApplication')
				voters = decisionVoters
				expressionHandler = ref('webExpressionHandler')
				boolean lowercase = conf.controllerAnnotations.lowercase // true
				if ('ant'.equals(conf.controllerAnnotations.matcher)) {
					urlMatcher = new AntUrlPathMatcher(lowercase)
				}
				else {
					urlMatcher = new RegexUrlPathMatcher(lowercase)
				}
				if (conf.rejectIfNoRule instanceof Boolean) {
					rejectIfNoRule = conf.rejectIfNoRule
				}
			}
		}
		else if (securityConfigType == 'Requestmap') {
			objectDefinitionSource(RequestmapMultipleVoterFilterInvocationDefinition) {
				voters = decisionVoters
				expressionHandler = ref('webExpressionHandler')
				urlMatcher = new AntUrlPathMatcher(true)
				if (conf.rejectIfNoRule instanceof Boolean) {
					rejectIfNoRule = conf.rejectIfNoRule
				}
			}
		}
		else if (securityConfigType == 'InterceptUrlMap') {
			objectDefinitionSource(InterceptUrlMapMultipleVoterFilterInvocationDefinition) {
				voters = decisionVoters
				expressionHandler = ref('webExpressionHandler')
				urlMatcher = new AntUrlPathMatcher(true)
				if (conf.rejectIfNoRule instanceof Boolean) {
					rejectIfNoRule = conf.rejectIfNoRule
				}
			}
		}

		SpringSecurityUtils.registerProvider 'otpAuthenticationProvider'
		SpringSecurityUtils.registerFilter 'otpAuthenticationFilter', SecurityFilterPosition.FORM_LOGIN_FILTER.order + 3
		SpringSecurityUtils.registerFilter 'twoFactorExceptionTranslationFilter', SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 1

		println '...finished configuring Spring Security OTP'
	}
}
