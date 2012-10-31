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

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.codehaus.groovy.grails.plugins.springsecurity.ReflectionUtils;
import org.springframework.security.web.FilterInvocation;

/**
 * Class based on Grails Spring Security Core's <code>org.codehaus.groovy.grails.plugins.springsecurity.IntercepUrlFilterInvocationDefinition</code>.
 *
 * @author <a href='mailto:rafael.luque@osoco.es'>Rafael Luque</a>
 */
public class InterceptUrlMapMultipleVoterFilterInvocationDefinition extends AbstractMultipleVoterFilterInvocationDefinition {

	private boolean _initialized;

	@Override
	protected String determineUrl(final FilterInvocation filterInvocation) {
		HttpServletRequest request = filterInvocation.getHttpRequest();
		String requestUrl = request.getRequestURI().substring(request.getContextPath().length());
		return lowercaseAndStripQuerystring(requestUrl);
	}

	@Override
	protected void initialize() {
		if (_initialized) {
			return;
		}

		reset();
	}

	@Override
	protected boolean stopAtFirstMatch() {
		return true;
	}

	@SuppressWarnings("unchecked")
	@Override
	public void reset() {
		Object map = ReflectionUtils.getConfigProperty("interceptUrlMap");
		if (!(map instanceof Map)) {
			_log.warn("interceptUrlMap config property isn't a Map");
			return;
		}

		resetConfigs();

		Map<String, List<String>> data = ReflectionUtils.splitMap((Map<String, Object>)map);
		for (Map.Entry<String, List<String>> entry : data.entrySet()) {
			compileAndStoreMapping(entry.getKey(), entry.getValue());
		}

		_initialized = true;
	}
}
