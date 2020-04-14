package testcode.oidc.nimbus;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;


import java.text.ParseException;
import java.util.Properties;

public class OidcIdTokenValidation {

    private Properties propertiesConfig;

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
