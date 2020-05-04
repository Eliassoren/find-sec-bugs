package testcode.oidc.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import org.slf4j.Logger;
import sun.security.util.Cache;
import testcode.oidc.util.nimbus.OidcConfig;


import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;

public class OidcValidateTokensNimbus {

    private Properties propertiesConfig;
    private Properties config;
    private Cache<String, Object> cache;
    private OIDCProviderMetadata providerMetadata;
    private URI callback;
    Logger logger;
    private IDTokenValidator idTokenValidator;


    // STEP 3 in flow chart
    public Response OK_tokenRequestValidateIdToken(OidcConfig oidcConfig, AuthorizationCode authorizationCode) {
        // Make the token request
        ClientID clientID = new ClientID(config.getProperty("client_id"));
        Secret clientSecret = new Secret(config.getProperty("client_secret"));
        TokenRequest tokenRequest = new TokenRequest(providerMetadata.getTokenEndpointURI(),
                new ClientSecretBasic(clientID, clientSecret),
                new AuthorizationCodeGrant(authorizationCode, callback));
        TokenResponse tokenResponse = null;
        try {
            tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send()); // TODO: Control flow: The state must be checked between trigger AuthenticationResponse and this exit point
            idTokenValidator = new IDTokenValidator(providerMetadata.getIssuer(),
                    clientID,
                    JWSAlgorithm.RS256,
                    providerMetadata.getJWKSetURI().toURL());
            if (!tokenResponse.indicatesSuccess()) {  // TODO: trigger for error handling and break control flow
                // We got an error response...
                TokenErrorResponse errorResponse = Objects.requireNonNull(tokenResponse).toErrorResponse();
                // Handle error response
                return Response.status(Response.Status.BAD_REQUEST).entity("Failed: "+errorResponse.getErrorObject().getCode()).build(); // TODO: Expect a return / break of control flow if there's an error response
            }
        } catch (IOException | com.nimbusds.oauth2.sdk.ParseException e) {
            // Handle exceptions
            Response.status(Response.Status.BAD_REQUEST).build();
        }
        try {
            OIDCTokenResponse successTokenResponse = (OIDCTokenResponse) Objects.requireNonNull(tokenResponse).toSuccessResponse();
            Nonce savedNonce = oidcConfig.nonce;
            idTokenValidator.validate(successTokenResponse.getOIDCTokens().getIDToken(), savedNonce);
            return Response
                    .ok(successTokenResponse.toJSONObject())
                    .build();
        } catch (JOSEException | BadJOSEException e) {
            // Error handling and break flow
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    public void validateToken(String idTokenString, Nonce expectedNonce) {
        // The required parameters
        Issuer iss = new Issuer("https://idp.example.com");
        ClientID clientID = new ClientID(propertiesConfig.getProperty("client_id"));
        JWSAlgorithm jwsAlg = JWSAlgorithm.RS256;
        Secret clientSecret = new Secret(propertiesConfig.getProperty("client_secret"));
        // Set the expected nonce, leave null if none
        // Create validator for signed ID tokens
        IDTokenValidator tokenValidator = new IDTokenValidator(iss, clientID, jwsAlg, clientSecret);
        JWT idToken = null;
        try {
            // Parse the ID token
           idToken  = JWTParser.parse(idTokenString);
        } catch (ParseException e) {
            // Error handling
        }


        IDTokenClaimsSet claims;

        try {
            claims = tokenValidator.validate(idToken, expectedNonce);
        } catch (BadJOSEException e) {
            // Invalid signature or claims (iss, aud, exp...)
        } catch (JOSEException e) {
            // Internal processing exception
        }
    }




}
