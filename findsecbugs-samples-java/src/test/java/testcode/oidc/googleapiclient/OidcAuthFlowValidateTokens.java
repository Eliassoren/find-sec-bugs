package testcode.oidc.googleapiclient;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.TokenRequest;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.http.GenericUrl;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import sun.security.util.Cache;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

public class OidcAuthFlowValidateTokens {


    private Properties config;
    private static final long DEFAULT_TIME_SKEW_SECONDS = 300;
    private AuthorizationCodeFlow authorizationCodeFlow;
    private AuthorizationCodeRequestUrl requestUrl;
    private PublicKey keyFromDiscoveryDocument;
    private Cache<String, Object> cache;
    Map<String, Object> providerMetadata;
    private String redirectUri = "https://client.com/callback";
    SecureRandom secureRandom;

    private class OidcConfig {
        public final String state;
        public final String nonce;
        public final UUID appuuid;
        public OidcConfig(String state, String nonce, UUID appuuid) {
            this.state = state;
            this.nonce = nonce;
            this.appuuid = appuuid;
        }
    }


    @SuppressFBWarnings("SERVLET_HEADER")
    public Response OK_callbackCheckState(HttpServletRequest callbackRequest) {
        try {
            UUID uuid = UUID.fromString(callbackRequest.getHeader("appuuid"));
            OidcConfig oidcConfig = (OidcConfig)cache.get(uuid);
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(callbackRequest.getRequestURI());
            String error = responseUrl.getError();
            if(error != null) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Authorization failed with error: "+error).build();
            }
            if(oidcConfig.state.equals(responseUrl.getState())) {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("The state does not match").build();
            }
            String authorizationCode = responseUrl.getCode();
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            return validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }
    public Response OK_tokenRequestVerifyMandatoryCallToOther(String authorizationCode, OidcConfig oidcConfig) {
        try {
            // After verified state and parse auth code..
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            return validateTokens(idTokenResponse, oidcConfig);
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    public Response tokenRequestGoogleTokenVerifier(String authorizationCode, OidcConfig oidcConfig) {
        try {
            // After verified state and parse auth code..
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
            IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
            if(idTokenVerifier.verify(idTokenResponse.parseIdToken())) {
                // Fixme: verifier is missing nonce and jwt check
                authorizationCodeFlow.createAndStoreCredential(idTokenResponse, oidcConfig.appuuid.toString());
                return Response.ok()
                        .entity(idTokenResponse)
                        .build();
            }
        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    public Response tokenRequestNoValidation(String authorizationCode, OidcConfig oidcConfig) {
        try {
            // After verified state and parse auth code..
            TokenRequest tokenRequest = authorizationCodeFlow.newTokenRequest(authorizationCode)
                    .setTokenServerUrl(new GenericUrl(authorizationCodeFlow.getTokenServerEncodedUrl()))
                    .setClientAuthentication(authorizationCodeFlow.getClientAuthentication())
                    .setRedirectUri(redirectUri);
            IdTokenResponse idTokenResponse = IdTokenResponse.execute(tokenRequest); // HTTP
           // No verification of id token...
            authorizationCodeFlow.createAndStoreCredential(idTokenResponse, oidcConfig.appuuid.toString());
            return Response.ok()
                    .entity(idTokenResponse)
                    .build();

        } catch (Exception e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    public Response validateTokens(IdTokenResponse tokenResponse, OidcConfig oidcConfig) throws IOException, GeneralSecurityException {
        IdToken idToken = tokenResponse.parseIdToken();
        if(!oidcConfig.nonce.equals(idToken.getPayload().getNonce())) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("The provided nonce did not match the one saved from the authorization request.")
                    .build();
        }
        if(!idToken.verifySignature(keyFromDiscoveryDocument)) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("The jwt signature is not valid.")
                    .build();
        }
        if(!idToken.verifyAudience(Collections.singleton(config.getProperty("clientId")))) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("This request does not seem like it was meant for this audience.")
                    .build();
        }
        if(!idToken.verifyExpirationTime(Instant.now().toEpochMilli(), DEFAULT_TIME_SKEW_SECONDS)){
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Token expired.")
                    .build();
        }
        // .... other checks
        authorizationCodeFlow.createAndStoreCredential(tokenResponse, oidcConfig.appuuid.toString());
        return Response.ok()
                .entity(tokenResponse)
                .build();
    }

}
