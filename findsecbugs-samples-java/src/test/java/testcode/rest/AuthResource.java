package testcode.rest;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;

@Path("/auth")
public class AuthResource {


    public AuthResource() {}

    @Path("login")
    @POST
    public Response login(@Context HttpHeaders headers, Map<String, String> body) {
        if(!body.containsKey("username") || !body.containsKey("password")) {
            throw new WebApplicationException("Missing username or password");
        }
        try {
            String username = body.get("username");
            Secret password = new Secret(body.get("password"));
            AuthorizationGrant passwordGrant =
                    new ResourceOwnerPasswordCredentialsGrant(username, password);

            HTTPResponse httpResponse = getHttpResponse(passwordGrant, getUserType(body));
            password.erase(); // FIXME bug; insecure practice. Should be in finally block. Bad control flow.
            handleErrorResponses(httpResponse);

            OIDCTokenResponse response = OIDCTokenResponse.parse(httpResponse);

            return getResponse(response);
        } catch (Exception e) {
            if(e instanceof ParseException) {
                throw new WebApplicationException("Error while parsing access token", e);
            }
            throw new WebApplicationException("Error getting access token", e); // FIXME bug: bad practice, should maybe give valid response
        }
    }

    @Path("refresh")
    @POST
    public Response refresh(@Context HttpHeaders headers, Map<String, String> body) {
        try {
            if(!body.containsKey("refreshToken")) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Refreshtoken was not found").build();
            }
            AuthorizationGrant refreshTokenGrant = new RefreshTokenGrant(new RefreshToken(body.get("refreshToken")));
            HTTPResponse httpResponse = getHttpResponse(refreshTokenGrant, getUserType(body));

            handleErrorResponses(httpResponse);
            OIDCTokenResponse response = OIDCTokenResponse.parse(httpResponse);

            return getResponse(response);
        } catch (Exception e) {
            throw new RuntimeException("Error getting access token", e);
        }
    }

    private Response getResponse(OIDCTokenResponse response) {
        OIDCTokenResponse successResponse = response.toSuccessResponse();

        OIDCTokens tokens = successResponse.getOIDCTokens();
        AccessToken accessToken = tokens.getAccessToken();
        RefreshToken refreshToken = tokens.getRefreshToken();
        return Response.ok()
                .entity(new OpenIdTokens(
                        tokens.getIDTokenString(),
                        accessToken != null ? accessToken.getValue() : null,
                        refreshToken != null ? refreshToken.getValue() : null))
                .build();
    }

    private HTTPResponse getHttpResponse(AuthorizationGrant passwordGrant, UserType userType) throws URISyntaxException, IOException {
        ClientAuthentication clientAuth = getClientAuthentication(userType);

        Scope scope = new Scope("profile", "openidconnect");

        String endpoint = userType == UserType.ADMIN ? "https://organization.com/api/admintoken":
                                                        "https://organization.com/api/token"; // USER
        URI tokenEndpoint = new URI(endpoint);

        TokenRequest request =
                new TokenRequest(
                        tokenEndpoint,
                        clientAuth,
                        passwordGrant,
                        scope,
                        null,
                        singletonMap("auth_chain", singletonList("oauth2chain")));

        HTTPRequest httpRequest = request.toHTTPRequest();

        httpRequest.setHeader("applicationguid", "ID");//getTransaction().getId());

        return httpRequest.send();
    }

    public enum UserType {
        USER,
        ADMIN
    }

    public static class OpenIdTokens {
        public final String idToken;
        public final String accessToken;
        public final String refreshToken;

        public OpenIdTokens(String idToken,
                            String accessToken,
                            String refreshToken) {
            this.idToken = idToken;
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }

    private ClientAuthentication getClientAuthentication(UserType userType) {
        if(userType == UserType.USER) {
            ClientID clientID = new ClientID(1);
            Secret clientSecret = new Secret(1);
            return new ClientSecretBasic(clientID, clientSecret);
        } else {
            ClientID clientID = new ClientID(1);
            Secret clientSecret = new Secret(1);
            return new ClientSecretBasic(clientID, clientSecret);
        }

    }

    private void handleErrorResponses(HTTPResponse httpResponse) throws ParseException {
            JSONObject responseBody = httpResponse.getContentAsJSONObject();
            String errorDescription = (String)responseBody.get("error_description");
            int statusCode = httpResponse.getStatusCode();
            if(statusCode == 401 || statusCode == 403 // FIXME bug: blacklist approach
            || statusCode == 400 && "invalid_grant".equals(responseBody.get("error"))) {
                throw new NotAuthorizedException(
                        statusCode,
                        "Unsuccessful login"
                );
            }

    }

    private UserType getUserType(Map<String, String> body) {
        String userType = body.get("user_type");
        if (userType == null || userType.equals("customer")) {
            return UserType.USER;
        } else if (userType.equals("admin")) {
            return UserType.ADMIN;
        } else {
            throw new WebApplicationException("Wrong user type");
        }
    }
}
