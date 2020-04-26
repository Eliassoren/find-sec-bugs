package testcode.oidc.nimbus;

import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.Json;
import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import net.minidev.json.JSONObject;
import org.apache.wicket.request.Request;
import testcode.juliet.IO;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.channels.ScatteringByteChannel;
import java.util.AbstractMap;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

public class OidcAuthRequestStateUsageRedirect {

    private Properties config;
    private OIDCProviderMetadata providerMetadata;
    private URI callback;
    private void processError(AuthenticationResponse response) {
            response.toErrorResponse();
        }
    private IDTokenValidator idTokenValidator;
    private OIDCProviderMetadata discovery() {
        try {
            URI issuerURI = new URI("https://provider.example.com/");
            URL providerConfigurationURL = issuerURI.resolve("/.well-known/openid-configuration?").toURL();
            HttpsURLConnection connection = (HttpsURLConnection)providerConfigurationURL.openConnection();
            if(!connection.getCipherSuite().equals("https")) {
                throw new SecurityException("Discovery url not using https.");

            }
            if(connection.getResponseCode() != HttpsURLConnection.HTTP_OK) {
                throw new SecurityException("Discovery failed to respond with HTTP response OK.");
            }
            InputStream stream = connection.getInputStream();
            // Read all data from URL
            String providerInfo;
            try (java.util.Scanner s = new java.util.Scanner(stream)) {
                providerInfo = s.useDelimiter("\\A").hasNext() ? s.next() : "";
            }
            return OIDCProviderMetadata.parse(providerInfo);
        } catch (ParseException | IOException | URISyntaxException e ) {
            // Handle
        }
        throw new RuntimeException("Failed to perform discovery");
    }

        // Doesn't add state param. Expect bug.
    @Path("/login")
    public Response authenticationRequestForgetAddState(HttpServletRequest request) {
        try {
            providerMetadata = discovery();
            HttpSession session = request.getSession();
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getProperty("client_id"));
            callback = new URI("https://client.com/callback");
            // Generate state string and nonce to mitigate CSRF
            State state =  new State();
            Nonce nonce = new Nonce();
            session.setAttribute("state", state);
            session.setAttribute("nonce", nonce);
            AuthenticationRequest req = new AuthenticationRequest(
                    providerMetadata.getAuthorizationEndpointURI(),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            return Response.seeOther(req.toURI()).build();
        } catch (URISyntaxException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    // Callback
    @Path("callback")
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
                    successResponse = Objects.requireNonNull(response).toSuccessResponse();
            // FIXME Forgotten to check the state here!!!!!

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
                // Create validator for signed ID tokens
                idTokenValidator = new IDTokenValidator(providerMetadata.getIssuer(),
                                                        clientID,
                                                        JWSAlgorithm.RS256,
                                                        providerMetadata.getJWKSetURI().toURL());
            } catch (IOException | ParseException e) {
                // Handle exceptions
            }
            if (!response.indicatesSuccess()) {
                // We got an error response...
                TokenErrorResponse errorResponse = Objects.requireNonNull(tokenResponse).toErrorResponse();
                errorResponse.getErrorObject();
                // Handle error response
            }

            OIDCTokenResponse successTokenResponse = (OIDCTokenResponse) Objects.requireNonNull(tokenResponse).toSuccessResponse();

            // Get the ID and access token, the server may also return a refresh token
            JWT idToken = successTokenResponse.getOIDCTokens().getIDToken();

            Nonce returnedNonce = Nonce.parse(idToken.getJWTClaimsSet().getStringClaim("nonce"));
            Nonce savedNonce = Nonce.parse(String.valueOf(httpAuthorizationCallback.getSession().getAttribute("nonce")));
            if(!savedNonce.equals(returnedNonce)) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Nonce not equal").build();
            }
            AccessToken accessToken = successTokenResponse.getOIDCTokens().getAccessToken();
            RefreshToken refreshToken = successTokenResponse.getOIDCTokens().getRefreshToken();

            return Response.ok()
                    .entity(successResponse)
                    .build();

        } catch (NullPointerException | java.text.ParseException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @Path("/login")
    public Response OK_authenticationRequestAddState(HttpServletRequest request) {
        try {
            providerMetadata = discovery();
            HttpSession session = request.getSession();
            // The client identifier provisioned by the server
            ClientID clientID = new ClientID(config.getProperty("client_id"));
            callback = new URI("https://client.com/callback");
            // Generate state string and nonce to mitigate CSRF
            State state =  new State();
            Nonce nonce = new Nonce();
            session.setAttribute("state", state);
            session.setAttribute("nonce", nonce);
            AuthenticationRequest req = new AuthenticationRequest(
                    providerMetadata.getAuthorizationEndpointURI(),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            return Response.seeOther(req.toURI()).build();
        } catch (URISyntaxException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    @Path("callback")
    public Response OK_callBackCheckStateAndNonce(HttpServletRequest httpAuthorizationCallback) {
        try {
            AuthenticationResponse
                    response = null;
            try { // This block is STEP 2 in flow chart.
                response = AuthenticationResponseParser.parse(new URI(httpAuthorizationCallback.getRequestURI())); // TODO:  Potential trigger AuthenticationResponse for state check
            } catch (ParseException | URISyntaxException e) {
                // Handle errors. Control flow must be broken here..
            }
            if (response instanceof AuthenticationErrorResponse) {
                // process error
                processError(response);
                return Response.status(Response.Status.BAD_REQUEST).entity("Error during authorization code flow").build();
            }
            AuthenticationSuccessResponse
                    successResponse = Objects.requireNonNull(response).toSuccessResponse(); // TODO: Potential trigger AuthenticationSuccessResponse for state check
            State returnedState = successResponse.getState();
            State savedState = State.parse(String.valueOf(httpAuthorizationCallback.getSession().getAttribute("state")));
            if(!returnedState.equals(savedState)) {  // TODO: Green flag if we have triggered.
                return Response.status(Response.Status.UNAUTHORIZED).entity("State does not match").build(); // TODO second aspect: check must follow a broken control flow.
            }
            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();
            // Make the token request
            ClientID clientID = new ClientID(config.getProperty("clientid"));
            Secret clientSecret = new Secret(config.getProperty("clientsecret"));
            TokenRequest tokenRequest = new TokenRequest(providerMetadata.getTokenEndpointURI(),
                                                    new ClientSecretBasic(clientID, clientSecret),
                                                    new AuthorizationCodeGrant(authorizationCode, callback));
            TokenResponse tokenResponse = null;
            try { // This symbolizes STEP 3 in flow char
                tokenResponse = OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send()); // TODO: Control flow: The state must be checked between trigger AuthenticationResponse and this exit point
                idTokenValidator = new IDTokenValidator(providerMetadata.getIssuer(),
                        clientID,
                        JWSAlgorithm.RS256,
                        providerMetadata.getJWKSetURI().toURL());
                if (!tokenResponse.indicatesSuccess()) {  // TODO: trigger for error handling and break control flow
                    // We got an error response...
                    TokenErrorResponse errorResponse = Objects.requireNonNull(tokenResponse).toErrorResponse();
                    errorResponse.getErrorObject();
                    // Handle error response
                    return Response.status(Response.Status.BAD_REQUEST).build(); // TODO: Expect a return / break of control flow if there's an error response
                }
            } catch (IOException | ParseException e) {
                // Handle exceptions
            }
            try {
                OIDCTokenResponse successTokenResponse = (OIDCTokenResponse) Objects.requireNonNull(tokenResponse).toSuccessResponse();
                Nonce savedNonce = Nonce.parse(String.valueOf(httpAuthorizationCallback.getSession().getAttribute("nonce")));
                idTokenValidator.validate(successTokenResponse.getOIDCTokens().getIDToken(), savedNonce);
                return Response
                        .ok(successTokenResponse.toJSONObject())
                        .build();
                //  if(!savedNonce.equals(returnedNonce)) {
                //    return Response.status(Response.Status.UNAUTHORIZED).entity("Nonce not equal").build(); // TODO: this check must be done before return OK, or returning the successresponse.
                // }
            } catch (JOSEException | BadJOSEException e) {
                // Error handling and break flow
                return Response.status(Response.Status.BAD_REQUEST).build(); // Consider requiring a return after each catch block to ensure that no exit point leads to an OK..
            }
        } catch (NullPointerException e) {
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



    private Response stateMatcherHandleResponse(AuthenticationSuccessResponse successResponse, State state) {
        if(!successResponse.getState().equals(state)) {
            // Unauthorized
            return Response.status(Response.Status.UNAUTHORIZED).build();
        }
        return Response.ok().build();
    }


}
