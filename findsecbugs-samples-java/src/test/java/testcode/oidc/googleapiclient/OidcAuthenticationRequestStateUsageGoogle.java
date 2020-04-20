package testcode.oidc.googleapiclient;

import com.google.api.client.auth.oauth2.*;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.testing.json.MockJsonFactory;
import com.nimbusds.oauth2.sdk.ParseException;


import testcode.android.R;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.SecureRandom;
import java.util.*;


public class OidcAuthenticationRequestStateUsageGoogle {
    /*
    * Use the authorization code flow to allow the end user to grant your application access to their protected data. The protocol for this flow is specified in the Authorization Code Grant specification.

This flow is implemented using AuthorizationCodeFlow. The steps are:

An end user logs in to your application. You need to associate that user with a user ID that is unique for your application.
Call AuthorizationCodeFlow.loadCredential(String), based on the user ID, to check if the user's credentials are already known. If so, you're done.
If not, call AuthorizationCodeFlow.newAuthorizationUrl() and direct the end user's browser to an authorization page where they can grant your application access to their protected data.
The web browser then redirects to the redirect URL with a "code" query parameter that can then be used to request an access token using AuthorizationCodeFlow.newTokenRequest(String).
Use AuthorizationCodeFlow.createAndStoreCredential(TokenResponse, String) to store and obtain a credential for accessing protected resources.
    * */

    private Properties config;

    private AuthorizationCodeFlow authorizationCodeFlow;
    private AuthorizationCodeRequestUrl requestUrl;
    SecureRandom secureRandom;

    private String nonce() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return new String(Base64.getEncoder().encode(randomBytes));
    }

    private String state() {
        return nonce();
    }


    // Doesn't add state param. Expect bug.
    public Response exampleAuthenticationRequestForgetAddState(HttpServletRequest request, HttpServletResponse response) {
        try {
           // String state =  nonce();
            //String nonce =  state();
            //request.getSession().setAttribute("state", state);
            authorizationCodeFlow = new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
                    new NetHttpTransport(), new MockJsonFactory(),
                    new GenericUrl("https://server.example.com/token"),
                    new BasicAuthentication(config.getProperty("clientId"), config.getProperty("clientSecret")),
                    config.getProperty("clientId"),
                    "https://server.example.com/authorize"
                    ).build();
            requestUrl = authorizationCodeFlow
                            .newAuthorizationUrl()
                            .setResponseTypes(Collections.singleton("code"))
                            .setScopes(Arrays.asList("openid", "email", "profile", "address"))
                            .setRedirectUri("https://client.com/callback");
                                                       //
            // .setState(state)
                                                      //  .set("Nonce", nonce);
            return Response.seeOther(requestUrl.toURI()).build();
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }
    @Path("/login")
    public Response OK_exampleAuthenticationRequestAddState(HttpServletRequest request, HttpServletResponse response) {
        try {
            String state =  nonce();
            String nonce =  state();
            request.getSession().setAttribute("state", state);
            authorizationCodeFlow = new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
                    new NetHttpTransport(), new MockJsonFactory(),
                    new GenericUrl("https://server.example.com/token"),
                    new BasicAuthentication(config.getProperty("clientId"), config.getProperty("clientSecret")),
                    config.getProperty("clientId"),
                    "https://server.example.com/authorize"
            ).build();
            requestUrl = authorizationCodeFlow
                    .newAuthorizationUrl()
                    .setResponseTypes(Collections.singleton("code"))
                    .setScopes(Arrays.asList("openid", "email", "profile", "address"))
                    .setRedirectUri("https://client.com/callback")
                    .setState(state)
                    .set("login_hint", request.getParameter("login_hint"))
                    .set("nonce", nonce);
            // todo: look at the flow. Maybe it will be forced to be separated with redirects. Makes sense. This
            // todo: means that the state set and the check may happen separately
            response.sendRedirect(requestUrl.toURI().toString());
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }


    // Callback catch. Doesn't echl state param. Expect bug.
    @Path("/callback")
    public Response exampleAuthenticationRequestForgetCheckState(HttpServletRequest callbackRequest, HttpServletResponse response) {
        try {
            String clientId = config.getProperty("clientId");
            if(!clientId.equals(callbackRequest.getParameter("aud"))) {
                // Not the right audience for request.
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Not the correct audience for request.").build();
            }

            if(callbackRequest.getSession().getAttribute("state")
                    .equals(callbackRequest.getParameter("state"))) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("The state does not match").build();
            }

            String authorizationCode = callbackRequest.getParameter("code");

            TokenResponse tokenResponse = authorizationCodeFlow.newTokenRequest(authorizationCode).execute();
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

}
