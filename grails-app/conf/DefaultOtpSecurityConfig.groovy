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

import es.osoco.grails.plugins.otp.web.OneTimePasswordAuthenticationFilter as OTPAF

security {

	otp {
		active = true

        /** User domain class specific properties */
        userLookup.secretKeyPropertyName = 'secretKey'

        /** Use a combined form for the two-factors or different forms */
        useTwoFactorsCombinedLoginForm = false

        /** Configuration compatible with Google Authentication app */
        totp.digits = 6
        totp.algorithm = 'HmacSHA1'

        /** Accepts neighbouring values to support clock drifts */
        totp.preStepsValidWindow = 1
        totp.postStepsValidWindow = 1

        /** Auth login pages */
        auth.loginFormUrl = '/login/authOTP'
        auth.ajaxLoginFormUrl = '/login/authOTPAjax'
        auth.combinedLoginFormUrl = '/login/authTwoFactors'
        auth.combinedAjaxLoginFormUrl = '/login/authTwoFactorsAjax'

        /** Auth config */
        auth.forceHttps = false
        auth.useForward = false

        /** Authentication processing filters */
        apf.filterProcessesUrl = '/j_spring_security_otp'
        apf.twoFactorsFilterProcessesUrl = '/j_spring_security_twofactors'
        apf.usernameParameter = OTPAF.SPRING_SECURITY_OTP_FORM_USERNAME_KEY // 'j_username'
        apf.passwordParameter = OTPAF.SPRING_SECURITY_OTP_FORM_PASSWORD_KEY // 'j_password'
        apf.otpParameter = OTPAF.SPRING_SECURITY_OTP_FORM_OTP_KEY // 'j_otp'
        apf.continueChainBeforeSuccessfulAuthentication = false
        apf.allowSessionCreation = true
        apf.postOnly = true
    }
}
