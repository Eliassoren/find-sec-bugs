package testcode.oidc.nimbus;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import sun.security.util.Cache;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;

public class OidcAuthFlowStateUsageRedirect {

    private Properties config;
    private Cache<String, Object> cache;
    private OIDCProviderMetadata providerMetadata;
    private URI callback;

    private void processError(AuthenticationResponse response) {
            response.toErrorResponse();
        }
    private IDTokenValidator idTokenValidator;

    private class OidcConfig {
        public final State state;
        public final Nonce nonce;
        public OidcConfig(State state, Nonce nonce) {
            this.state = state;
            this.nonce = nonce;
        }
    }

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
    // @Path("/login")
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


            cache.put(state.getValue(), new OidcConfig(state, nonce));
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

    // STEP 1
    @SuppressFBWarnings("SERVLET_HEADER")
    public Response callBackMissingCheckState(HttpServletRequest httpAuthorizationCallback) {
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
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();
            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            // FIXME: security error, missing state check
            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();

            return OK_tokenRequestValidateIdToken(oidcConfig, authorizationCode);
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

   // @Path("/login")
    // Step 1
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
            UUID uuid = UUID.randomUUID();
            cache.put(uuid.toString(), ImmutableMap.of("state", state,
                                                       "nonce", nonce
            ));
            AuthenticationRequest req = new AuthenticationRequest(
                    providerMetadata.getAuthorizationEndpointURI(),
                    new ResponseType("code"),
                    Scope.parse("openid email profile address"),
                    clientID,
                    callback,
                    state,
                    nonce);
            return Response.seeOther(req.toURI()).header("appuuid", uuid).build();
        } catch (URISyntaxException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    // @Path("callback")
    // STEP 2
    @SuppressFBWarnings("SERVLET_HEADER")
    public Response OK_callBackCheckState(HttpServletRequest httpAuthorizationCallback) {
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
            String appuuid = UUID.fromString(httpAuthorizationCallback.getHeader("appuuid")).toString();

            OidcConfig oidcConfig = (OidcConfig)cache.get(appuuid);
            State savedState = oidcConfig.state;
            if(!returnedState.equals(savedState)) {  // TODO: Green flag if we have triggered.
                return Response.status(Response.Status.UNAUTHORIZED).entity("State does not match").build(); // TODO second aspect: check must follow a broken control flow.
            }
            AuthorizationCode authorizationCode = successResponse.getAuthorizationCode();
           return OK_tokenRequestValidateIdToken(oidcConfig, authorizationCode);
        } catch (NullPointerException | ClassCastException e) {
            // Error handling
        }
        return Response.status(Response.Status.UNAUTHORIZED).build();
    }

    // STEP 3 in flow chart
    private Response OK_tokenRequestValidateIdToken(OidcConfig oidcConfig, AuthorizationCode authorizationCode) {
        // Make the token request
        ClientID clientID = new ClientID(config.getProperty("clientid"));
        Secret clientSecret = new Secret(config.getProperty("clientsecret"));
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
                errorResponse.getErrorObject();
                // Handle error response
                return Response.status(Response.Status.BAD_REQUEST).build(); // TODO: Expect a return / break of control flow if there's an error response
            }
        } catch (IOException | ParseException e) {
            // Handle exceptions
        }
        try {
            OIDCTokenResponse successTokenResponse = (OIDCTokenResponse) Objects.requireNonNull(tokenResponse).toSuccessResponse();
            Nonce savedNonce = oidcConfig.nonce;
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
    }



    // Doesn't check state. Expect bug.
    private void stateMatcherHandleNoMatch(AuthenticationSuccessResponse successResponse, State state) {
        successResponse.toParameters();
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
