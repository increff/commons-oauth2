/*
 * Copyright (c) 2021. Increff
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package com.increff.commons.oauth2;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import com.google.api.client.auth.oauth2.TokenResponse;

@Controller
@RequestMapping(value = "/oauth2")
public class OAuth2Controller {

	private static String oauth2Url = "https://accounts.google.com/o/oauth2/auth";

	@Value("${oauth2.clientId}")
	private String oauth2ClientId;
	@Value("${oauth2.clientSecret}")
	private String oauth2ClientSecret;

	@Value("${oauth2.redirectUri}")
	private String oauth2RedirectUri;
	@Value("${oauth2.appRedirectUri}")
	private String appRedirectUri;

	// redirects to the OAuth2 URL
	@RequestMapping(value = "/init", method = RequestMethod.GET)
	public RedirectView init(HttpServletRequest req, @RequestParam String hd, RedirectAttributes redirectAttributes) {
		// Clear session
		HttpSession session = req.getSession();
		OAuth2Api.clearUser(session);
		// Redirect
		redirectAttributes.addAttribute("access_type", "offline");
		redirectAttributes.addAttribute("client_id", oauth2ClientId);
		redirectAttributes.addAttribute("prompt", "select_account");
		redirectAttributes.addAttribute("redirect_uri", oauth2RedirectUri);
		redirectAttributes.addAttribute("response_type", "code");
		redirectAttributes.addAttribute("scope", "email");
		return new RedirectView(oauth2Url + "?hd=" + hd);
	}

	@RequestMapping(value = "/redirect", method = RequestMethod.GET)
	public RedirectView redirect(HttpServletRequest req, @RequestParam(required = false) String error,
			@RequestParam(required = false) String code, @RequestParam(required = false) String scope)
			throws IOException {
		HttpSession session = req.getSession();
		if (error != null) {
			OAuth2Api.setError(session, error);
			// Redirect
			return new RedirectView(appRedirectUri, true);
		}
		OAuth2TokenForm form = new OAuth2TokenForm();
		form.setClientId(oauth2ClientId);
		form.setClientSecret(oauth2ClientSecret);
		form.setCode(code);
		form.setGrantType("authorization_code");
		form.setRedirectUrl(oauth2RedirectUri);

		TokenResponse response = null;
		try {
			response = OAuth2Api.getToken(form);
		} catch (IOException e) {
			throw e;
		}
		// Get access token and JWT
		// Create the oAuth2User

		OAuth2Api.setUser(session, response);
		// Redirect
		return new RedirectView(appRedirectUri, true);
	}

}
