package testcode.oidc.nimbus;

import com.google.api.client.auth.openidconnect.IdToken;
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
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.AccessTokenValidator;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import com.nimbusds.openid.connect.sdk.validators.InvalidHashException;
import org.slf4j.Logger;
import sun.security.util.Cache;
import testcode.android.R;
import testcode.oidc.util.nimbus.OidcConfig;


import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
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
        TokenResponse tokenResponse;
        try {
            tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
            if (!tokenResponse.indicatesSuccess()) {  // TODO: trigger for error handling and break control flow
                // We got an error response...
                ErrorObject errorObject = Objects.requireNonNull(tokenResponse).toErrorResponse().getErrorObject();
                return Response.status(Response.Status.UNAUTHORIZED)
                               .entity("Token request failed with code: "+errorObject.getCode())
                               .build();
            }
        } catch (IOException | com.nimbusds.oauth2.sdk.ParseException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Parsing of token response failed.").build();
        }
        try { // Validate ID token - required!
            JWSAlgorithm metadataAlg = providerMetadata.getIDTokenJWSAlgs().contains(JWSAlgorithm.RS256)?
                                        JWSAlgorithm.RS256 // Recommended in OIDC specification.
                                        : JWSAlgorithm.HS256; // Stated as required in SDK. Could assume it exists.
            idTokenValidator = new IDTokenValidator(providerMetadata.getIssuer(),
                    clientID,
                    JWSAlgorithm.RS256,
                    providerMetadata.getJWKSetURI().toURL()); // JWKsetUri contains the keys from the IdP
            OIDCTokenResponse successTokenResponse = (OIDCTokenResponse)tokenResponse.toSuccessResponse();
            Nonce savedNonce = oidcConfig.nonce;
            JWT idToken = successTokenResponse.getOIDCTokens().getIDToken();

            idTokenValidator.validate(idToken, savedNonce);
            // Todo: valid to store tokens in DB
            return Response
                    .ok(successTokenResponse.toJSONObject()) // Contains ID Token, access token, optionally refresh token...
                    .build();
        } catch (BadJOSEException e) {
            // Error handling and break flow
            return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid ID token").build();
        } catch (JOSEException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Error while validating ID token.").build();
        }
        catch (MalformedURLException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("The provider metadata jwkSetUri is invalid").build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Something went wrong during token validation").build();
        }
    }

    private Response.ResponseBuilder validateAccessToken(JWT idToken, AccessToken accessToken) {
        try {
            JWSAlgorithm idTokenJwsAlgorithm =  (JWSAlgorithm)idToken.getHeader().getAlgorithm();
            // throws parseexception if claim is not found
            AccessTokenHash atHash = new AccessTokenHash(idToken.getJWTClaimsSet().getStringClaim("at_hash"));
            AccessTokenValidator.validate(accessToken,
                    idTokenJwsAlgorithm,
                    atHash);
        } catch (java.text.ParseException e) {
            // We have no hash. Cannot validate access token. We should then let things pass unless we requre this from idp...
        } catch (InvalidHashException e) {
            // "Access token is not valid")
            return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid access token");
        }
        return Response.ok();
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
        } catch (java.text.ParseException e) {
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
