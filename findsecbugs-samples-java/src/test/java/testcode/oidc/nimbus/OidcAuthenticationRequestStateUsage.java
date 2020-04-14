package testcode.oidc.nimbus;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.*;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Properties;

public class OidcAuthenticationRequestStateUsage {
    private Properties config;

    private void processError(AuthenticationResponse response) {
        response.toErrorResponse();
    }

    // Doesn't check state param. Expect bug.
    public Response exampleAuthenticationRequestForgetCheckState() {
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
                // process error
                processError(response);
            }
            AuthenticationSuccessResponse
                    successResponse = response.toSuccessResponse();
            // Don't forget to check the state
           // if(!successResponse.getState().equals(state)) {
             //   return Response.status(Response.Status.UNAUTHORIZED).build();
           // }
            return Response.ok()
                    .entity(successResponse)
                    .build();
        } catch (URISyntaxException | ParseException | ClassCastException | IOException e) {
            // Error handling
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
            AuthenticationSuccessResponse successResponse =  response.toSuccessResponse();
            return stateMatcherHandleResponse(successResponse, state);
        } catch (URISyntaxException e) {
        } catch (IOException e) {
        } catch (ParseException e) {
        } catch (ClassCastException e) {
        }
        return Response.status(Response.Status.FORBIDDEN).build();
    }
}
