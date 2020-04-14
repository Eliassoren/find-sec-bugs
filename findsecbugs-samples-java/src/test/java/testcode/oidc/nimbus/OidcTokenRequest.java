package testcode.oidc.nimbus;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Properties;

public class OidcTokenRequest {
    private Properties propertiesConfig;
    private AuthorizationCode authorizationCode;
    private URI callbackUri; // Ex. "https://client.com/callback"


    public void exampleTokenRequest() {
        try {
            // Construct the code grant from the code obtained from the authz endpoint
            // and the original callback URI used at the authz endpoint
            AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authorizationCode, callbackUri);

            // The credentials to authenticate the client at the token endpoint
            ClientID clientID = new ClientID(propertiesConfig.getProperty("clientid"));
            Secret clientSecret = new Secret(propertiesConfig.getProperty("clientsecret"));
            ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

            // The token endpoint
            URI tokenEndpoint = new URI("https://c2id.com/token");

            // Make the token request
            TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

            TokenResponse response = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());

            if (!response.indicatesSuccess()) {
                // We got an error response...
                TokenErrorResponse errorResponse = response.toErrorResponse();

            }

            OIDCTokenResponse successResponse = (OIDCTokenResponse)response.toSuccessResponse();

            // Get the ID and access token, the server may also return a refresh token
            JWT idToken = successResponse.getOIDCTokens().getIDToken();

            AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
            RefreshToken refreshToken = successResponse.getOIDCTokens().getRefreshToken();



        } catch(URISyntaxException e) {

        } catch (IOException e) {

        } catch (ParseException e) {

        }

    }
}
