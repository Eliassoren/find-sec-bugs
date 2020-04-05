package com.h3xstream.findsecbugs.oauth2;

public class ImproperStateUsageOidcDetector {

    // Forget to use state altogether
    // Forget comparing state after receiving response to authorization request.

    /* TODO:
    foundAuthContext = false // This must be true to trigger the search for state verification
    foundStateVerify = false; // This must be true in the end to be safe. Optionally -- add check for random method where state is passed as param or state class-wide accessible?

    for each method in javaclass:
        if method contains invokespecial authContext and State:
        foundAuthContext = true;
            for each instruction in method:
             if instruction == invokevirtual AND signature is "State.equal":
                  foundStateVerify = true
       end
    end
end

if (foundAuthContext AND NOT foundStateVerify):
    report bug --> "forgot to check state
end
     */

}


/*
    // Initiators:

    31: invokespecial #11                 // Method com/nimbusds/oauth2/sdk/id/State."<init>":()V

    - AuthenticationRequest with a State object in params:
    - We at least need to look for such a call to be sure that we are in an authentication request context
    - ... in which we would also somewhere expect a State comparison..

   83: invokespecial #22 Method com/nimbusds/openid/connect/sdk/AuthenticationRequest."<init>":(
    Ljava/net/URI;Lcom/nimbusds/oauth2/sdk/ResponseType;
    Lcom/nimbusds/oauth2/sdk/Scope;
    Lcom/nimbusds/oauth2/sdk/id/ClientID;
    Ljava/net/URI;Lcom/nimbusds/oauth2/sdk/id/State; -----------
    Lcom/nimbusds/openid/connect/sdk/Nonce;)V


    // Closer
     135: invokevirtual #30                 // Method com/nimbusds/oauth2/sdk/id/State.equals:(Ljava/lang/Object;)Z ***

     // Interprocedural limitation:
     - If we call a function in which state is passed, or/and checked, we should invalidate the warning...
     - Or maybe give a weaker priority warning just "remember to check state". Did you remember to verify state value in "methodCall(state, request...)
*/


/*ode/oauth2/OidcAuthenticationRequest.class
Compiled from "OidcAuthenticationRequest.java"
public class testcode.oauth2.OidcAuthenticationRequest {
  public testcode.oauth2.OidcAuthenticationRequest();
    Code:
       0: aload_0
       1: invokespecial #1                  // Method java/lang/Object."<init>":()V
       4: return

  public void exampleAuthenticationRequestForgetCheckState();
    Code:
       0: new           #2                  // class com/nimbusds/oauth2/sdk/id/ClientID
       3: dup
       4: aload_0
       5: getfield      #3                  // Field config:Ljava/util/Properties;
       8: ldc           #4                  // String client_id
      10: invokevirtual #5                  // Method java/util/Properties.getProperty:(Ljava/lang/String;)Ljava/lang/String;
      13: invokespecial #6                  // Method com/nimbusds/oauth2/sdk/id/ClientID."<init>":(Ljava/lang/String;)V
      16: astore_1
      17: new           #7                  // class java/net/URI
      20: dup
      21: ldc           #8                  // String https://client.com/callback
      23: invokespecial #9                  // Method java/net/URI."<init>":(Ljava/lang/String;)V
      26: astore_2
      27: new           #10                 // class com/nimbusds/oauth2/sdk/id/State
      30: dup
      31: invokespecial #11                 // Method com/nimbusds/oauth2/sdk/id/State."<init>":()V
      34: astore_3
      35: new           #12                 // class com/nimbusds/openid/connect/sdk/Nonce
      38: dup
      39: invokespecial #13                 // Method com/nimbusds/openid/connect/sdk/Nonce."<init>":()V
      42: astore        4
      44: new           #14                 // class com/nimbusds/openid/connect/sdk/AuthenticationRequest
      47: dup
      48: new           #7                  // class java/net/URI
      51: dup
      52: ldc           #15                 // String https://c2id.com/login
      54: invokespecial #9                  // Method java/net/URI."<init>":(Ljava/lang/String;)V
      57: new           #16                 // class com/nimbusds/oauth2/sdk/ResponseType
      60: dup
      61: iconst_1
      62: anewarray     #17                 // class java/lang/String
      65: dup
      66: iconst_0
      67: ldc           #18                 // String code
      69: aastore
      70: invokespecial #19                 // Method com/nimbusds/oauth2/sdk/ResponseType."<init>":([Ljava/lang/String;)V
      73: ldc           #20                 // String openid email profile address
      75: invokestatic  #21                 // Method com/nimbusds/oauth2/sdk/Scope.parse:(Ljava/lang/String;)Lcom/nimbusds/oauth2/sdk/Scope;
      78: aload_1
      79: aload_2
      80: aload_3
      81: aload         4
      83: invokespecial #22                 // Method com/nimbusds/openid/connect/sdk/AuthenticationRequest."<init>":(Ljava/net/URI;Lcom/nimbusds/oauth2/sdk/ResponseType;Lcom/nimbusds/oauth2/sdk/Scope;Lcom/nimbusds/oauth2/sdk/id/ClientID;Ljava/net/URI;Lcom/nimbusds/oauth2/sdk/id/State;Lcom/nimbusds/openid/connect/sdk/Nonce;)V
      86: astore        5
      88: aload         5
      90: invokevirtual #23                 // Method com/nimbusds/openid/connect/sdk/AuthenticationRequest.toHTTPRequest:()Lcom/nimbusds/oauth2/sdk/http/HTTPRequest;
      93: invokevirtual #24                 // Method com/nimbusds/oauth2/sdk/http/HTTPRequest.send:()Lcom/nimbusds/oauth2/sdk/http/HTTPResponse;
      96: astore        6
      98: aload         6
     100: invokestatic  #25                 // Method com/nimbusds/openid/connect/sdk/AuthenticationResponseParser.parse:(Lcom/nimbusds/oauth2/sdk/http/HTTPResponse;)Lcom/nimbusds/openid/connect/sdk/AuthenticationResponse;
     103: astore        7
     105: aload         7
     107: instanceof    #26                 // class com/nimbusds/openid/connect/sdk/AuthenticationErrorResponse
     110: ifeq          113
     113: aload         7
     115: invokeinterface #27,  1           // InterfaceMethod com/nimbusds/openid/connect/sdk/AuthenticationResponse.toSuccessResponse:()Lcom/nimbusds/openid/connect/sdk/AuthenticationSuccessResponse;
     120: astore        8
     122: aload         8
     124: invokevirtual #28                 // Method com/nimbusds/openid/connect/sdk/AuthenticationSuccessResponse.getAuthorizationCode:()Lcom/nimbusds/oauth2/sdk/AuthorizationCode;
     127: astore        9
     129: aload         8
     131: invokevirtual #29                 // Method com/nimbusds/openid/connect/sdk/AuthenticationSuccessResponse.getState:()Lcom/nimbusds/oauth2/sdk/id/State;
     134: aload_3
     135: invokevirtual #30                 // Method com/nimbusds/oauth2/sdk/id/State.equals:(Ljava/lang/Object;)Z
     138: ifne          141
     141: goto          157
     144: astore_1
     145: goto          157
     148: astore_1
     149: goto          157
     152: astore_1
     153: goto          157
     156: astore_1
     157: return
    Exception table:
       from    to  target type
           0   141   144   Class java/net/URISyntaxException
           0   141   148   Class java/io/IOException
           0   141   152   Class com/nimbusds/oauth2/sdk/ParseException
           0   141   156   Class java/lang/ClassCastException
*/