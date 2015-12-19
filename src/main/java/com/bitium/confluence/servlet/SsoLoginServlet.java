/**
 * Confluence SAML Plugin - a confluence plugin to allow SAML 2.0
 *	authentication. 
 *
 *	Copyright (C) 2014 Bitium, Inc.
 *	
 *	This file is part of Confluence SAML Plugin.
 *	
 *	Confluence SAML Plugin is free software: you can redistribute it 
 *	and/or modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation, either version 3 of
 *	the License, or (at your option) any later version.
 *	
 *	Confluence SAML Plugin is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with Pineapple. If not, see <http://www.gnu.org/licenses/>.
 */
package com.bitium.confluence.servlet;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.schema.XSAny;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import com.atlassian.confluence.user.ConfluenceUser;
import com.atlassian.seraph.auth.Authenticator;
import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.seraph.config.SecurityConfigFactory;
import com.bitium.confluence.config.SAMLConfluenceConfig;
import com.bitium.saml.SAMLContext;


public class SsoLoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private Log log = LogFactory.getLog(SsoLoginServlet.class);

	private SAMLConfluenceConfig saml2Config;

	@Override
	public void init() throws ServletException {
		super.init();
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {

		//Initial idea was to pass os_destination when we do OneLogin redirection via loginAuth.js.
		//But easier way is, use http referer which already has this information! So that's what we are doing here.
		//If os_destination parameter is not null, it means user wants to go to specific protected URL after authentication.
		//Let's put this parameter and it's value in session so that we can redirect User later to this desired destination!
		//This parameter gets in action in doPost method via authenticateUserAndLogin()!
		String refererURL = request.getHeader("Referer");
		String os_destination = null;
		if (refererURL != null) {
			try{
				URI url = new URI(refererURL);
				String queryString = url.getRawQuery();
				if (queryString != null){
					String[] params = queryString.split("&");
					for (String param: params) {
						String key = param.substring(0, param.indexOf('='));
						if (key.equals("os_destination")){
							String val = param.substring(param.indexOf('=') + 1);
							os_destination = java.net.URLDecoder.decode(val, "UTF-8");
						}
					}
				}
			}
			catch (java.net.URISyntaxException urs){
				//Do nothing as os_destination is already initialized to null!
			}
		}

		if (os_destination != null) {
			request.getSession().setAttribute("os_destination", os_destination);
		}

		try {
			SAMLContext context = new SAMLContext(request, saml2Config);
			SAMLMessageContext messageContext = context.createSamlMessageContext(request, response);

			// Generate options for the current SSO request
	        WebSSOProfileOptions options = new WebSSOProfileOptions();
	        options.setBinding(org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI);
                options.setIncludeScoping(false);

			// Send request
	        WebSSOProfile webSSOprofile = new WebSSOProfileImpl(context.getSamlProcessor(), context.getMetadataManager());
	        webSSOprofile.sendAuthenticationRequest(messageContext, options);
		} catch (Exception e) {
		    log.error("saml plugin error + " + e.getMessage());
			response.sendRedirect("/confluence/login.action?samlerror=general");
		}
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException {
		try {
			SAMLContext context = new SAMLContext(request, saml2Config);
			SAMLMessageContext messageContext = context.createSamlMessageContext(request, response);

			// Process response
	        context.getSamlProcessor().retrieveMessage(messageContext);

	        messageContext.setLocalEntityEndpoint(SAMLUtil.getEndpoint(messageContext.getLocalEntityRoleMetadata().getEndpoints(), messageContext.getInboundSAMLBinding(), request.getRequestURL().toString()));
	        messageContext.getPeerEntityMetadata().setEntityID(saml2Config.getIdpEntityId());

	        WebSSOProfileConsumer consumer = new WebSSOProfileConsumerImpl(context.getSamlProcessor(), context.getMetadataManager());
	        SAMLCredential credential = consumer.processAuthenticationResponse(messageContext);

	        request.getSession().setAttribute("SAMLCredential", credential);

//	        String userName = ((XSAny)credential.getAttributes().get(0).getAttributeValues().get(0)).getTextContent();
                String userName = credential.getNameID().getValue();

	        authenticateUserAndLogin(request, response, userName);
		} catch (AuthenticationException e) {
			try {
			    log.error("saml plugin error + " + e.getMessage());
				response.sendRedirect("/confluence/login.action?samlerror=plugin_exception");
			} catch (IOException e1) {
				throw new ServletException();
			}
		} catch (Exception e) {
			try {
			    log.error("saml plugin error + " + e.getMessage());
				response.sendRedirect("/confluence/login.action?samlerror=plugin_exception");
			} catch (IOException e1) {
				throw new ServletException();
			}
		}
	}

	private void authenticateUserAndLogin(HttpServletRequest request,
			HttpServletResponse response, String username)
			throws NoSuchMethodException, IllegalAccessException,
			InvocationTargetException, IOException {
		Authenticator authenticator = SecurityConfigFactory.getInstance().getAuthenticator();

		if (authenticator instanceof DefaultAuthenticator) {
			//DefaultAuthenticator defaultAuthenticator = (DefaultAuthenticator)authenticator;

		    Method getUserMethod = DefaultAuthenticator.class.getDeclaredMethod("getUser", new Class[]{String.class});
		    getUserMethod.setAccessible(true);
		    Object userObject = getUserMethod.invoke(authenticator, new Object[]{username});
		    if(userObject != null && userObject instanceof ConfluenceUser) {
		    	Principal principal = (Principal)userObject;

		    	Method authUserMethod = DefaultAuthenticator.class.getDeclaredMethod("authoriseUserAndEstablishSession",
		    			new Class[]{HttpServletRequest.class, HttpServletResponse.class, Principal.class});
		    	authUserMethod.setAccessible(true);
		    	Boolean result = (Boolean)authUserMethod.invoke(authenticator, new Object[]{request, response, principal});

				// If User has accessed specific protected URL, then we should honor that request.
				// os_destination parameter will help us here to do exactly same!
				if (result) {
					if(request.getSession() != null && request.getSession().getAttribute("os_destination") != null) {
						String os_destination = request.getSession().getAttribute("os_destination").toString();
						response.sendRedirect(os_destination);
					} else {
						String redirectUrl = saml2Config.getRedirectUrl();
						if (redirectUrl == null || redirectUrl.equals("")) {
							redirectUrl = "/confluence/dashboard.action";
						}
						response.sendRedirect(redirectUrl);
					}
					return;
				}
		    }
		}

		response.sendRedirect("/confluence/login.action?samlerror=user_not_found");
	}

	public void setSaml2Config(SAMLConfluenceConfig saml2Config) {
		this.saml2Config = saml2Config;
	}


}
