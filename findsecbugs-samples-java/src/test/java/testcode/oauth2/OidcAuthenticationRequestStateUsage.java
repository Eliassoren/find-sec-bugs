package testcode.oauth2;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.*;
import org.springframework.security.core.Authentication;

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
    public void exampleAuthenticationRequestForgetCheckState() {
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
                processError(response);
            }

            // Don't forget to check the state
           // if(!successResponse.getState().equals(state)) {
                // Unauthorized
           // }
        } catch (URISyntaxException | ParseException | ClassCastException e) {
            //
        } catch (IOException e) {
            // Handle differently
        }
    }

    public void OK_exampleAuthenticationRequestForgetCheckState() {
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
            AuthorizationCode code = successResponse.getAuthorizationCode();
            // Don't forget to check the state
             if(!successResponse.getState().equals(state)) {
                // Unauthorized
            }
        } catch (URISyntaxException e) {
        } catch (IOException e) {
        } catch (ParseException e) {
        } catch (ClassCastException e) {

        }
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
