package testcode.oidc.nimbus;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.apache.wicket.request.Request;
import testcode.juliet.IO;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.channels.ScatteringByteChannel;
import java.util.Properties;

public class OidcAuthRequestStateUsageRedirect {

    private Properties config;
    private OIDCProviderMetadata providerMetadata;
    private URI callback;
    private Nonce savedNonce;
    private State savedState;
    private void processError(AuthenticationResponse response) {
            response.toErrorResponse();
        }

    private void discovery() {
        try {
            URI issuerURI = new URI("http://provider.example.com/");
            URL providerConfigurationURL = issuerURI.resolve("/.well-known/openid-configuration").toURL();
            InputStream stream = providerConfigurationURL.openStream();
            // Read all data from URL
            String providerInfo = null;
            try (java.util.Scanner s = new java.util.Scanner(stream)) {
                providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
            }
            providerMetadata = OIDCProviderMetadata.parse(providerInfo);
        } catch (Exception e ) {
            // Handle
        }
    }

        // Doesn't check state param. Expect bug.
    public Response exampleAuthenticationRequestForgetAddState(HttpServletRequest request) {
        try {
            discovery();
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getProperty("client_id"));
            callback = new URI("https://client.com/callback");
            // Generate state string and nonce to mitigate CSRF
           // savedState =  new State();
            // savedNonce = new Nonce();
            AuthenticationRequest req = new AuthenticationRequest(
                    new URI("https://c2id.com/login"),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    null,
                    null);
            return Response.seeOther(req.toURI()).build();
        } catch (URISyntaxException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    // Callback
    public Response callBackForgetCheckState(HttpServletRequest httpAuthorizationCallback) {
        try {
            AuthenticationResponse
                    response = null;
            try {
                response = AuthenticationResponseParser.parse(new URI(httpAuthorizationCallback.getRequestURI()));
            } catch (ParseException | URISyntaxException e) {
                // Handle
            }
            if (response instanceof AuthenticationErrorResponse) {
                // process error
                processError(response);
            }
            AuthenticationSuccessResponse
                    successResponse = response.toSuccessResponse();
            // FIXME Don't forget to check the state here!!!!!
            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();
            // Make the token request
            ClientID clientID = new ClientID(config.getProperty("clientid"));
            Secret clientSecret = new Secret(config.getProperty("clientsecret"));
            ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
            TokenRequest request = new TokenRequest(providerMetadata.getTokenEndpointURI(),
                    clientAuth,
                    new AuthorizationCodeGrant(authorizationCode, callback));
            TokenResponse tokenResponse = null;
            try {
                tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());
            } catch (IOException | ParseException e) {
                // Handle exceptions
            }

            if (!response.indicatesSuccess()) {
                // We got an error response...
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
            }

            OIDCTokenResponse successTokenResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

            // Get the ID and access token, the server may also return a refresh token
            JWT idToken = successTokenResponse.getOIDCTokens().getIDToken();

            Nonce returnedNonce = Nonce.parse((String)idToken.getJWTClaimsSet().getClaim("nonce"));

            if(!savedNonce.equals(returnedNonce)) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Nonce not equal").build();
            }
            AccessToken accessToken = successTokenResponse.getOIDCTokens().getAccessToken();
            RefreshToken refreshToken = successTokenResponse.getOIDCTokens().getRefreshToken();



            return Response.ok()
                    .entity(successResponse)
                    .build();

        } catch (NullPointerException | java.text.ParseException e) {
        // Errror handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    public Response OK_exampleSafeAuthenticationRequest() {
        try {
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getProperty("client_id"));
            URI callback = new URI("https://client.com/callback");
            // Generate state string and nonce to mitigate CSRF
            State state = new State();
            Nonce nonce = new Nonce();
            AuthenticationRequest req = new AuthenticationRequest(
                    new URI("https://c2id.com/login"),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            HTTPResponse httpResponse = req.toHTTPRequest().send();
            AuthenticationResponse
                    response = AuthenticationResponseParser.parse(httpResponse);
            if (response instanceof AuthenticationErrorResponse) {
                processError(response);
            }
            AuthenticationSuccessResponse
                    successResponse = response.toSuccessResponse();
            // Don't forget to check the state
            if(!successResponse.getState().equals(state)) {
                return Response.status(Response.Status.UNAUTHORIZED).build();
            }
            return Response.ok()
                    .entity(successResponse)
                    .build();

        } catch (URISyntaxException | ParseException | ClassCastException | IOException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    // Doesn't check state. Expect bug.
    private void stateMatcherHandleNoMatch(AuthenticationSuccessResponse successResponse, State state) {
        successResponse.toParameters();
    }

    // Calls to method that doesn't check state. Expect bug.
    public void exampleAuthenticationRequestForgetCheckStateInCallToOther() {
        // Pass state to method with no verification
        try {
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getProperty("client_id"));
            URI callback = new URI("https://client.com/callback");
            // Generate random state string and nonce for pairing the response to the request
            State state = new State();
            Nonce nonce = new Nonce();
            AuthenticationRequest req = new AuthenticationRequest(
                    new URI("https://c2id.com/login"),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            HTTPResponse httpResponse = req.toHTTPRequest().send(); // Step 3
            AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse); // Step 7
            if (response instanceof AuthenticationErrorResponse) {
                // process error
            }
            AuthenticationSuccessResponse successResponse =  response.toSuccessResponse();
            stateMatcherHandleNoMatch(successResponse, state);
        } catch (URISyntaxException e) {
        } catch (IOException e) {
        } catch (ParseException e) {
        } catch (ClassCastException e) {
        }
    }


    private void stateMatcherHandle(AuthenticationSuccessResponse successResponse,State state) {
        if(!successResponse.getState().equals(state)) {
            // Unauthorized
        }
    }


    public void OK_exampleAuthenticationRequestForgetCheckState_2() {
        // Pass state to method
        try {
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getProperty("client_id"));
            URI callback = new URI("https://client.com/callback");
            // Generate random state string and nonce for pairing the response to the request
            State state = new State();
            Nonce nonce = new Nonce();
            AuthenticationRequest req = new AuthenticationRequest(
                    new URI("https://c2id.com/login"),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            HTTPResponse httpResponse = req.toHTTPRequest().send(); // Step 3
            AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse); // Step 7
            if (response instanceof AuthenticationErrorResponse) {
                // process error
            }
            AuthenticationSuccessResponse successResponse =  response.toSuccessResponse();
            stateMatcherHandle(successResponse, state);
        } catch (URISyntaxException e) {
        } catch (IOException e) {
        } catch (ParseException e) {
        } catch (ClassCastException e) {

        }
    }


    private Response stateMatcherHandleResponse(AuthenticationSuccessResponse successResponse, State state) {
        if(!successResponse.getState().equals(state)) {
            // Unauthorized
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        return Response.ok().build();
    }

    public Response OK_exampleAuthenticationRequestForgetCheckState_3() {
        // Pass state to method
        try {
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getProperty("client_id"));
            URI callback = new URI("https://client.com/callback");
            // Generate random state string and nonce for pairing the response to the request
            State state = new State();
            Nonce nonce = new Nonce();
            AuthenticationRequest req = new AuthenticationRequest(
                    new URI("https://c2id.com/login"),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            HTTPResponse httpResponse = req.toHTTPRequest().send(); // Step 3
            AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse); // Step 7
            if (response instanceof AuthenticationErrorResponse) {
                // process error
            }
            AuthenticationSuccessResponse successResponse = response.toSuccessResponse();
            return stateMatcherHandleResponse(successResponse, state);
        } catch (URISyntaxException e) {
        } catch (IOException e) {
        } catch (ParseException e) {
        } catch (ClassCastException e) {
        }
        return Response.status(Response.Status.FORBIDDEN).build();
    }

}
