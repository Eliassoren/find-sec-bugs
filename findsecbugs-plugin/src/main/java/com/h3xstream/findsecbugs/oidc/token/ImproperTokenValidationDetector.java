package com.h3xstream.findsecbugs.oidc.token;

import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import com.h3xstream.findsecbugs.oidc.data.AnalyzedMethodStateUsage;
import com.h3xstream.findsecbugs.oidc.data.CalledMethodIdentifiers;
import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Hierarchy;
import edu.umd.cs.findbugs.ba.JavaClassAndMethod;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.*;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class ImproperTokenValidationDetector implements Detector {
    private final BugReporter bugReporter;
    private static final String MISSING_VERIFY_ID_TOKEN = "MISSING_VERIFY_ID_TOKEN";
    private static final String EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN = "EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN";


    private Map<MethodAnnotation, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheckForeignMethod = new HashMap<>();
    private Map<CalledMethodIdentifiers, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheckForeignNotFound = new HashMap<>();
    private Map<Method, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheck = new HashMap<>();
    JavaClass javaClass;
    private static final InvokeMatcherBuilder
            TOKEN_REQUEST_NIMBUS = invokeInstruction()
            .atClass("com/nimbusds/openid/connect/sdk/AuthenticationResponseParser")
            .atMethod("parse")
            .withArgs("(Ljava/net/URI;)Lcom/nimbusds/openid/connect/sdk/AuthenticationResponse;");

    private static final InvokeMatcherBuilder
            TOKEN_REQUEST_GOOGLE = invokeInstruction()
            .atClass("com/google/api/client/auth/oauth2/AuthorizationCodeResponseUrl")
            .atMethod("<init>")
            .withArgs("(Ljava/lang/String;)V");// TODO: generalize statement. This trigger should be configurable

    private static final InvokeMatcherBuilder
            GET_STATE_METHOD = invokeInstruction()
            .atClass("com/nimbusds/openid/connect/sdk/AuthenticationResponse",
                    "com/google/api/client/auth/oauth2/AuthorizationCodeResponseUrl")
            .atMethod("getState");

    private static final InvokeMatcherBuilder
            NIMBUS_TOKEN_VERIFY_SDK = invokeInstruction() //
            .atClass("Method com/nimbusds/openid/connect/sdk/validators/IDTokenValidator")
            .atMethod("validate")
            .withArgs("(Lcom/nimbusds/jwt/JWT;Lcom/nimbusds/openid/connect/sdk/Nonce;)Lcom/nimbusds/openid/connect/sdk/claims/IDTokenClaimsSet;"); // TODO: generalize. More params should be checked. In Googleapi, strings are used. May want to evaluate for certain variable names to be sure.

    private static final InvokeMatcherBuilder
            GOOGLE_TOKEN_VERIFY_SDK = invokeInstruction() //
            .atClass("java/lang/String")
            .atMethod("equals")
            .withArgs("(Ljava/lang/Object;)Z");
    private static final String TOKEN_VARIABLE_NAME_REGEX = "state"; // TODO: add possible variations

    private static final List<InvokeMatcherBuilder> TOKEN_REQUEST_VARIATIONS = Arrays.asList(
            TOKEN_REQUEST_NIMBUS,
            TOKEN_REQUEST_GOOGLE
    );


    private static final List<InvokeMatcherBuilder> STATE_EQUALS_INVOKE_VARIATIONS = Arrays.asList(
            NIMBUS_TOKEN_VERIFY_SDK
    );

    private boolean looksLikeStateVerify(Instruction instruction, ConstantPoolGen cpg, boolean indicationsOfStateVar) {
        return (STATE_EQUALS_INVOKE_VARIATIONS.stream().anyMatch(i -> i.matches(instruction, cpg))) // Tightly defined state type
                || (GOOGLE_TOKEN_VERIFY_SDK.matches(instruction, cpg) && indicationsOfStateVar); // String with name
    }

    private boolean looksLikeIdTokenPassedParam(InvokeInstruction invokeInstruction, ConstantPoolGen cpg, boolean foundGetState) {
        boolean idTokenParameterNimbus =
                 (invokeInstruction.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/TokenResponse;")
                         && !invokeInstruction.getSignature(cpg).endsWith("Lcom/nimbusds/oauth2/sdk/TokenResponse;"));
                 // Google SDK
         boolean idTokenParameterGoogle =  (invokeInstruction.getSignature(cpg).contains("Lcom/google/api/client/auth/openidconnect/IdTokenResponse;") // google
                        && !invokeInstruction.getSignature(cpg).endsWith("Lcom/google/api/client/auth/openidconnect/IdTokenResponse;"))
               || (invokeInstruction.getSignature(cpg).contains("Lcom/google/api/client/auth/openidconnect/IdToken;")
                        && !invokeInstruction.getSignature(cpg).endsWith("Lcom/google/api/client/auth/openidconnect/IdToken;"));
        // Todo generalize strings. We have two factors: actually passing the thing, while not returning it. Maybe this itself is bad. Maybe we validate AND return the token?
        return idTokenParameterNimbus || idTokenParameterGoogle;
    }

    private void saveStatePassedAsParam(ConstantPoolGen cpg, InvokeInstruction invokeInstruction, AnalyzedMethodStateUsage analyzedMethodStateUsage) {
        Method calledMethod = findLocalMethodWithName(javaClass,
                invokeInstruction.getMethodName(cpg),
                invokeInstruction.getClassName(cpg));
        if(calledMethod == null) { // The method called is not in this java class
            try {
                JavaClassAndMethod exactMethod = Hierarchy.findExactMethod(invokeInstruction, cpg);
                MethodAnnotation methodAnnotation = MethodAnnotation.fromXMethod(exactMethod.toXMethod());
                methodCallersThatShouldHaveStateCheckForeignMethod.put(
                        methodAnnotation, analyzedMethodStateUsage);
            } catch (ClassNotFoundException e) {
                CalledMethodIdentifiers calledMethodIdentifiers = new CalledMethodIdentifiers(
                        invokeInstruction.getClassName(cpg),
                        invokeInstruction.getMethodName(cpg),
                        invokeInstruction.getSignature(cpg)
                );
                methodCallersThatShouldHaveStateCheckForeignNotFound.put(
                        calledMethodIdentifiers,
                        analyzedMethodStateUsage);
            }
        } else {
            methodCallersThatShouldHaveStateCheck.put(
                    calledMethod,
                    analyzedMethodStateUsage);
        }
    }

    public ImproperTokenValidationDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {

        javaClass = classContext.getJavaClass();
        boolean foundTokenRequest = false;
        boolean foundTokenPassedAsParamToPossibleCheck = false; // We pass state outside of the procedure and need an additional check.
        boolean foundGetIdToken = false; //method based on callback response Method com/google/api/client/auth/oauth2/AuthorizationCodeResponseUrl.getState:()Ljava/lang/String;
        boolean foundTokenVerify = false;
        Method[] methods = javaClass.getMethods();
        List<Method> methodsWithStateCheck = new ArrayList<>();
        methodCallersThatShouldHaveStateCheckForeignMethod = new HashMap<>();
        methodCallersThatShouldHaveStateCheckForeignNotFound = new HashMap<>();
        methodCallersThatShouldHaveStateCheck = new HashMap<>();

        // Call to a method where state param is called, and caller.

        for (Method m : methods) {
            foundTokenPassedAsParamToPossibleCheck = false;
            foundGetIdToken = false;
            foundTokenRequest = false;
            foundTokenVerify = false;
            MethodGen methodGen = classContext.getMethodGen(m);

            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }
            if(methodGen.getName().toLowerCase().contains("state")
                    || Arrays.stream(m.getLocalVariableTable()
                    .getLocalVariableTable())
                    .anyMatch(name -> name.getName().matches(TOKEN_VARIABLE_NAME_REGEX)
                            || name.getSignature().contains("Lcom/nimbusds/oauth2/sdk/id/State;"))) {
                // Localvariabletable

            }

            for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
                Instruction instruction = instructionHandle.getInstruction();
                if(!(instruction instanceof InvokeInstruction)) {
                    continue;
                }
                InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;


                if(looksLikeIdTokenPassedParam(invokeInstruction, cpg, foundGetIdToken)
                        && foundTokenRequest
                        && !foundTokenPassedAsParamToPossibleCheck
                        && !foundTokenVerify){
                    // FIXME: we must ensure that this looks for something that may do "verify", either by throwing or returning boolean. FP risk: passing on and continuing verify
                    // TODO: look at logic. Null now.
                    foundTokenPassedAsParamToPossibleCheck = true;


                    boolean calledMethodContainsTokenInName = invokeInstruction.getMethodName(cpg).contains("token");

                }
            }

            if (foundTokenRequest && !foundTokenVerify && !foundTokenPassedAsParamToPossibleCheck) {
                bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_ID_TOKEN, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }
        }


        if(!methodCallersThatShouldHaveStateCheck.isEmpty()) {
            for(Method localCalledMethod : methodCallersThatShouldHaveStateCheck.keySet()) {
                AnalyzedMethodStateUsage analyzedMethod = methodCallersThatShouldHaveStateCheck.get(localCalledMethod);
                if(analyzedMethod.notClearedAndPossiblyPassesCheck) {
                    if(!methodsWithStateCheck.contains(localCalledMethod)) {
                        reportInterproceduralMethodCall(javaClass,
                                localCalledMethod,
                                analyzedMethod.method);
                    }
                }
            }
        }


        if(!methodCallersThatShouldHaveStateCheckForeignMethod.isEmpty()) {
            for(MethodAnnotation calledMethodAnnotation : methodCallersThatShouldHaveStateCheckForeignMethod.keySet()) {
                AnalyzedMethodStateUsage analyzedMethod = methodCallersThatShouldHaveStateCheckForeignMethod.get(calledMethodAnnotation);
                if(analyzedMethod.notClearedAndPossiblyPassesCheck) {
                    reportInterproceduralMethodCall(
                            javaClass,
                            calledMethodAnnotation,
                            analyzedMethod.method
                    );
                }
            }
        }

        if(!methodCallersThatShouldHaveStateCheckForeignNotFound.isEmpty()) {
            for(CalledMethodIdentifiers calledMethodIdentifiers: methodCallersThatShouldHaveStateCheckForeignNotFound.keySet()) {
                AnalyzedMethodStateUsage analyzedMethod = methodCallersThatShouldHaveStateCheckForeignNotFound.get(calledMethodIdentifiers);
                if(analyzedMethod.notClearedAndPossiblyPassesCheck) {
                    reportInterproceduralMethodCall(
                            javaClass,
                            calledMethodIdentifiers,
                            analyzedMethod.method);
                }
            }
        }
    }

    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 Method locallyCalledMethod,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_ID_TOKEN, Priorities.HIGH_PRIORITY)
                .addClassAndMethod(javaClass, callerMethod));
        bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_ID_TOKEN, Priorities.HIGH_PRIORITY)
                .addClassAndMethod(javaClass, locallyCalledMethod));
    }

    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 MethodAnnotation lookupCalledMethod,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN, Priorities.LOW_PRIORITY)
                .addClassAndMethod(javaClass, callerMethod)
                .addCalledMethod(lookupCalledMethod.toXMethod()));
    }


    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 CalledMethodIdentifiers lookupCalledMethodIdentifiers,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN, Priorities.LOW_PRIORITY)
                .addClassAndMethod(javaClass, callerMethod)
                .addString(lookupCalledMethodIdentifiers.toString()));

    }

    private Method findLocalMethodWithName(JavaClass javaClass, String methodName, String methodClassName) {
        if(!methodClassName.equals(javaClass.getClassName())) {
            return null;
        }
        return Arrays.stream(javaClass.getMethods())
                .filter(m -> m.getName().equals(methodName))
                .findAny()
                .orElse(null);
    }



    @Override
    public void report() {

    }
}
