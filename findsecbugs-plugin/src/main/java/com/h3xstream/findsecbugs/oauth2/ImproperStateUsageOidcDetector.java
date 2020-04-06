package com.h3xstream.findsecbugs.oauth2;

import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.bcp.Invoke;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;
import org.sonarqube.ws.client.WsRequest;

import java.util.*;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class ImproperStateUsageOidcDetector implements Detector {

    // Forget to use state altogether
    // Forget comparing state after receiving response to authorization request.


    private BugReporter bugReporter;
    private static final String FORGOT_VERIFY_OIDC_STATE = "FORGOT_VERIFY_OIDC_STATE";
    private static final String POSSIBLY_FORGOT_VERIFY_OIDC_STATE = "POSSIBLY_FORGOT_VERIFY_OIDC_STATE";
    private static final InvokeMatcherBuilder
            AUTH_REQUEST_INIT = invokeInstruction() //
                                .atClass("com/nimbusds/openid/connect/sdk/AuthenticationRequest")
                                .atMethod("<init>");

    private static final InvokeMatcherBuilder
            STATE_EQUALS_METHOD = invokeInstruction() //
                                    .atClass("com/nimbusds/oauth2/sdk/id/State")
                                    .atMethod("equals")
                                    .withArgs("(Ljava/lang/Object;)Z");
    public ImproperStateUsageOidcDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {
        JavaClass javaClass = classContext.getJavaClass();
        boolean foundAuthContext; // This must be true to trigger the search for state verification
        boolean foundStateVerify; // This must be true in the end to be safe.
        boolean foundStatePassedAsParamToPossibleCheck; // This lowers the risk.
        Method[] methodList = javaClass.getMethods();
        List<Method> methodsWithStateCheck = new ArrayList<>();
        Map<String, Method> methodCallsThatShouldHaveStateCheck = new HashMap<>(); // Call to a method where state param is called.
        for (Method m : methodList) {
            foundAuthContext = false;
            foundStateVerify = false;
            foundStatePassedAsParamToPossibleCheck = false;
            MethodGen methodGen = classContext.getMethodGen(m);


            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }
            for (Iterator<InstructionHandle> itIns = methodGen.getInstructionList().iterator(); itIns.hasNext();) {
                Instruction instruction = itIns.next().getInstruction();
                if (instruction instanceof INVOKESPECIAL) {
                    INVOKESPECIAL invoke = (INVOKESPECIAL) instruction;
                    if (AUTH_REQUEST_INIT.matches(instruction, cpg) &&
                            invoke.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/id/State;")) {
                        foundAuthContext = true;
                    } else if (invoke.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/id/State;") &&
                                (invoke.getSignature(cpg).endsWith(")V") || // void call
                                !invoke.getSignature(cpg).endsWith("Lcom/nimbusds/openid/connect/sdk/AuthenticationResponse;"))) {
                        foundStatePassedAsParamToPossibleCheck = true;
                        methodCallsThatShouldHaveStateCheck.put(invoke.getMethodName(cpg), m);
                    }

                }
                else if (instruction instanceof INVOKEVIRTUAL) {
                    if (STATE_EQUALS_METHOD.matches(instruction, cpg)) {
                        foundStateVerify = true;
                        methodsWithStateCheck.add(m);
                    }
                }
            }


            if (foundAuthContext && !foundStateVerify && !foundStatePassedAsParamToPossibleCheck) {
                bugReporter.reportBug(new BugInstance(this, FORGOT_VERIFY_OIDC_STATE, Priorities.NORMAL_PRIORITY) //
                        .addClassAndMethod(javaClass, m));
            } else if(foundAuthContext && foundStatePassedAsParamToPossibleCheck) {
               // bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE, Priorities.LOW_PRIORITY) //
                 //       .addClassAndMethod(javaClass, m));
            }
        }

        for (String calledMethodName : methodCallsThatShouldHaveStateCheck.keySet()) {
            Method method = findMethodWithName(javaClass, calledMethodName);
            Method callerMethod = methodCallsThatShouldHaveStateCheck.get(calledMethodName);
            if(method != null && !hasStateCheck(method, methodsWithStateCheck)) {
                bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE, Priorities.LOW_PRIORITY) //
                        .addClassAndMethod(javaClass, callerMethod));
                bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE, Priorities.LOW_PRIORITY) //
                        .addClassAndMethod(javaClass, method));
            }
        }
    }

    private Method findMethodWithName(JavaClass javaClass, String methodName) {
       for(Method m : javaClass.getMethods()) {
           if(methodName.equals(m.getName())) {
               return m;
           }
       }
       return null;
    }

    private boolean hasStateCheck(Method m, List<Method> methodsWithStateCheck) {
        return methodsWithStateCheck.contains(m);
    }

    @Override
    public void report() {

    }
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
    Ljava/net/URI;Lcom/nimbusds/oauth2/sdk/id/State;
    Lcom/nimbusds/openid/connect/sdk/Nonce;)V


    // Closers
     135: invokevirtual #30                 // Method com/nimbusds/oauth2/sdk/id/State.equals:(Ljava/lang/Object;)Z ***

       // If the state class is passed to a method we can make an assumption that stuff happens there
    126: invokespecial #37      // Method stateMatcherHandle:(Lcom/nimbusds/openid/connect/sdk/AuthenticationSuccessResponse;Lcom/nimbusds/oauth2/sdk/id/State;)V



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