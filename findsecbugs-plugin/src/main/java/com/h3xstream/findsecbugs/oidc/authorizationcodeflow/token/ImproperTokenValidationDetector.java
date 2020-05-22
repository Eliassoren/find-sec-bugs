/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.oidc.authorizationcodeflow.token;

import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import com.h3xstream.findsecbugs.oidc.data.AnalyzedMethodPeepholes;
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
    private static final String MISSING_VERIFY_NONCE = "MISSING_VERIFY_NONCE";
    private static final String INCOMPLETE_ID_TOKEN_VERIFICATION = "INCOMPLETE_ID_TOKEN_VERIFICATION";
    private static final String USING_INCOMPLETE_ID_TOKEN_VALIDATOR = "USING_INCOMPLETE_ID_TOKEN_VALIDATOR";
    private static final String EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN = "EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN";



    private Map<MethodAnnotation, AnalyzedMethodPeepholes> methodCallersThatShouldHaveCheckForeignMethod = new HashMap<>();
    private Map<CalledMethodIdentifiers, AnalyzedMethodPeepholes> methodCallersThatShouldHaveCheckForeignNotFound = new HashMap<>();
    private Map<Method, AnalyzedMethodPeepholes> methodCallersThatShouldHaveVerify = new HashMap<>();
    JavaClass javaClass;
    private static final InvokeMatcherBuilder
            TOKENREQUEST_EXECUTE_NIMBUS = invokeInstruction()
            .atClass("com/nimbusds/openid/connect/sdk/OIDCTokenResponseParser")
            .atMethod("parse");
           // .withArgs("(Lcom/nimbusds/oauth2/sdk/http/HTTPResponse;)Lcom/nimbusds/oauth2/sdk/TokenResponse");

    private static final InvokeMatcherBuilder
            TOKENREQUEST_EXECUTE_GOOGLE = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdTokenResponse")
            .atMethod("execute")
            .withArgs("(Lcom/google/api/client/auth/oauth2/TokenRequest;)Lcom/google/api/client/auth/openidconnect/IdTokenResponse;");// TODO: generalize statement. This trigger should be configurable

    // TOKEN-execute com/google/api/client/auth/openidconnect/IdTokenResponse.execute:(Lcom/google/api/client/auth/oauth2/TokenRequest;)Lcom/google/api/client/auth/openidconnect/IdTokenResponse;

    private static final List<InvokeMatcherBuilder> TOKENREQUEST_VARIATIONS = Arrays.asList(
            TOKENREQUEST_EXECUTE_NIMBUS,
            TOKENREQUEST_EXECUTE_GOOGLE
    );


    private static final InvokeMatcherBuilder
            PARSE_ID_TOKEN_GOOGLE = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdTokenResponse")
            .atMethod("parseIdToken");


    private static final InvokeMatcherBuilder
        GET_ID_TOKEN_NIMBUS = invokeInstruction()
            .atClass("com/nimbusds/openid/connect/sdk/token/OIDCTokens")
            .atMethod("getIDToken")
            .withArgs("()Lcom/nimbusds/jwt/JWT;");

    private static final List<InvokeMatcherBuilder> GET_TOKEN_VARIATIONS = Arrays.asList(
            PARSE_ID_TOKEN_GOOGLE,
            GET_ID_TOKEN_NIMBUS
    );

    private static final InvokeMatcherBuilder
            NIMBUS_TOKEN_VERIFY_SDK = invokeInstruction() //
            .atClass("com/nimbusds/openid/connect/sdk/validators/IDTokenValidator")
            .atMethod("validate")
            .withArgs("(Lcom/nimbusds/jwt/JWT;Lcom/nimbusds/openid/connect/sdk/Nonce;)Lcom/nimbusds/openid/connect/sdk/claims/IDTokenClaimsSet;"); // TODO: generalize. More params should be checked. In Googleapi, strings are used. May want to evaluate for certain variable names to be sure.


    private static final InvokeMatcherBuilder
            GOOGLE_TOKEN_VERIFY_SDK = invokeInstruction() // missing crypto key and nonce
            .atClass("com/google/api/client/auth/openidconnect/IdTokenVerifier")
            .atMethod("verify")
            .withArgs("(Lcom/google/api/client/auth/openidconnect/IdToken;)Z");

private static final InvokeMatcherBuilder
            GOOGLE_INTERNAL_TOKEN_VERIFY_SDK = invokeInstruction() // missing nonce check but has crypto
            .atClass("com/google/api/client/googleapis/auth/oauth2/GoogleIdTokenVerifier")
            .atMethod("verify")
            .withArgs("(Lcom/google/api/client/auth/openidconnect/IdToken;)Z");


    private static final String TOKEN_VARIABLE_NAME_REGEX_PATTERN = "token"; // TODO: add possible variations
    private static final String VERIFY_REGEXPATTERN = ".*verify|valid.*"; // TODO: add possible variations


    private static final List<InvokeMatcherBuilder> INCOMPLETE_TOKEN_VERIFY_SDK_METHOD = Arrays.asList(
            GOOGLE_TOKEN_VERIFY_SDK,
            GOOGLE_INTERNAL_TOKEN_VERIFY_SDK
    );

    private static final List<InvokeMatcherBuilder> TOKEN_VERIFY_SDK_VARIATIONS = Arrays.asList(
            NIMBUS_TOKEN_VERIFY_SDK
    );

    private final InvokeMatcherBuilder
            GOOGLE_ID_TOKEN_GET_NONCE = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdToken$Payload")
            .atMethod("getNonce");
    private final InvokeMatcherBuilder
            STRING_EQUALS = invokeInstruction()
            .atClass("java/lang/String")
            .atMethod("equals")
            .withArgs("(Ljava/lang/Object;)Z");

    private static final InvokeMatcherBuilder
        GOOGLE_VERIFY_ISSUER = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdToken")
            .atMethod("verifyIssuer")
            .withArgs("(Ljava/lang/String;)Z");
    private static final InvokeMatcherBuilder
        GOOGLE_VERIFY_AUD = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdToken")
            .atMethod("verifyAudience")
            .withArgs("(Ljava/util/Collection;)Z");

    private static final InvokeMatcherBuilder
        GOOGLE_VERIFY_SIGNATURE= invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdToken")
            .atMethod("verifySignature");


    private static final InvokeMatcherBuilder
        GOOGLE_VERIFY_EXP= invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdToken")
            .atMethod("verifyTime", "verifyExpirationTime", "verifyIssuedAtTime"); // todo: add verify exptime and iat as variation

    private static final List<InvokeMatcherBuilder> TOKEN_VERIFY_REQUIRED_CHECKS = Arrays.asList(
            GOOGLE_VERIFY_ISSUER,
            GOOGLE_VERIFY_AUD,
            GOOGLE_VERIFY_SIGNATURE,
            GOOGLE_VERIFY_EXP
    );


    private boolean looksLikeManualTokenVerify(MethodGen methodGen, ConstantPoolGen cpg) {
        boolean foundTokenVerifyMethod = false;
        if (methodGen == null || methodGen.getInstructionList() == null) {
            return false; //No instruction .. nothing to do
        }
        for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
            Instruction instruction = instructionHandle.getInstruction();
            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            if(TOKEN_VERIFY_REQUIRED_CHECKS.stream().anyMatch(c -> c.matches(instruction, cpg))) {
                foundTokenVerifyMethod = true;
            }
        }
        return foundTokenVerifyMethod || hasVerifyNonce(methodGen, cpg);
    }



    private boolean looksLikeValidTokenSDKVerify(Instruction instruction, ConstantPoolGen cpg, boolean indicationsOfVariableToVerify) {
        return (TOKEN_VERIFY_SDK_VARIATIONS.stream().anyMatch(i -> i.matches(instruction, cpg)));
    }

    private boolean hasVerifySignature(MethodGen methodGen, ConstantPoolGen cpg) {
        boolean hasVerifySignature = false;
        for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
            Instruction instruction = instructionHandle.getInstruction();
            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            if(GOOGLE_VERIFY_SIGNATURE.matches(instruction, cpg)) {
                hasVerifySignature = true;
            }
            if(GOOGLE_INTERNAL_TOKEN_VERIFY_SDK.matches(instruction, cpg)) {
                hasVerifySignature = true;
            }
        }
        return hasVerifySignature;
    }

    private boolean hasVerifyNonce(MethodGen methodGen, ConstantPoolGen cpg) {
        boolean hasStringEquals = false;
        boolean hasGetNonce = false;
        for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
            Instruction instruction = instructionHandle.getInstruction();
            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            if (STRING_EQUALS.matches(instruction, cpg)) {
                hasStringEquals = true;
            } else if (GOOGLE_ID_TOKEN_GET_NONCE.matches(instruction, cpg)) {
                hasGetNonce = true;
            }
        }
       return hasGetNonce && hasStringEquals;
    }

    private void verifyThatAllChecksAreThere(Method m, MethodGen methodGen, ConstantPoolGen cpg) {
        boolean foundVerifyIss = false;
        boolean foundVerifyAud = false;
        boolean foundVerifySignatureCrypto = false;
        boolean foundVerifyNonce = false;
        boolean foundVerifyExp = false;

        if (methodGen == null || methodGen.getInstructionList() == null) {
            return; //No instruction .. nothing to do
        }
        for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
            Instruction instruction = instructionHandle.getInstruction();
            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            if(GOOGLE_VERIFY_ISSUER.matches(instruction, cpg)) {
                foundVerifyIss = true;
            } else if(GOOGLE_VERIFY_AUD.matches(instruction, cpg)) {
                foundVerifyAud = true;
            } else if(GOOGLE_VERIFY_SIGNATURE.matches(instruction, cpg)) {
                foundVerifySignatureCrypto = true;
            } else if(GOOGLE_VERIFY_EXP.matches(instruction, cpg)) {
                foundVerifyExp = true;
            }
        }

        boolean completeVerify = foundVerifyIss
                                && foundVerifyAud
                                && foundVerifySignatureCrypto
                                && foundVerifyExp;

        if(!completeVerify) {
            bugReporter.reportBug(new BugInstance(this, INCOMPLETE_ID_TOKEN_VERIFICATION, Priorities.NORMAL_PRIORITY)
                    .addClassAndMethod(javaClass, m));
        }
        if(!hasVerifyNonce(methodGen, cpg)) {
            bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_NONCE, Priorities.NORMAL_PRIORITY)
                    .addClassAndMethod(javaClass, m));
        }
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

    private void savePassedAsParam(ConstantPoolGen cpg, InvokeInstruction invokeInstruction, AnalyzedMethodPeepholes analyzedMethodPeepholes) {
        Method calledMethod = findLocalMethodWithName(javaClass,
                invokeInstruction.getMethodName(cpg),
                invokeInstruction.getClassName(cpg));
        if(calledMethod == null) { // The method called is not in this java class
            try {
                JavaClassAndMethod exactMethod = Hierarchy.findExactMethod(invokeInstruction, cpg);
                MethodAnnotation methodAnnotation = MethodAnnotation.fromXMethod(exactMethod.toXMethod());
                methodCallersThatShouldHaveCheckForeignMethod.put(
                        methodAnnotation, analyzedMethodPeepholes);
            } catch (ClassNotFoundException e) {
                CalledMethodIdentifiers calledMethodIdentifiers = new CalledMethodIdentifiers(
                        invokeInstruction.getClassName(cpg),
                        invokeInstruction.getMethodName(cpg),
                        invokeInstruction.getSignature(cpg)
                );
                methodCallersThatShouldHaveCheckForeignNotFound.put(
                        calledMethodIdentifiers,
                        analyzedMethodPeepholes);
            }
        } else {
            methodCallersThatShouldHaveVerify.put(
                    calledMethod,
                    analyzedMethodPeepholes);
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
        boolean foundGetIdToken = false;
        boolean foundTokenVerifyCall = false;
        boolean tokenInMethodSignature = false;
        boolean foundIncompleteValidatorSDK = false;
        Method[] methods = javaClass.getMethods();
        List<Method> methodsWithVerify = new ArrayList<>();
        List<Method> methodsRequireAllTokenChecks = new ArrayList<>();
        methodCallersThatShouldHaveCheckForeignMethod = new HashMap<>();
        methodCallersThatShouldHaveCheckForeignNotFound = new HashMap<>();
        methodCallersThatShouldHaveVerify = new HashMap<>();

        // Call to a method where state param is called, and caller.

        for (Method m : methods) {
            foundTokenPassedAsParamToPossibleCheck = false;
            foundGetIdToken = false;
            foundTokenRequest = false;
            foundTokenVerifyCall = false;
            tokenInMethodSignature = false;
            foundIncompleteValidatorSDK = false;
            MethodGen methodGen = classContext.getMethodGen(m);

            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }
            try {
                if (methodGen.getName().toLowerCase().contains("token")
                        || m.getLocalVariableTable() != null && Arrays.stream(m.getLocalVariableTable()
                        .getLocalVariableTable())
                        .anyMatch(mth -> mth.getName().matches(TOKEN_VARIABLE_NAME_REGEX_PATTERN)
                                ||
                                (mth.getSignature().contains("Lcom/nimbusds/jwt/JWT;")
                                        || mth.getSignature().contains("Lcom/google/api/client/auth/openidconnect/IdToken"))
                        )) {
                    // Localvariabletable
                    tokenInMethodSignature = true;
                }
            } catch (Exception e) {
                // Could fail in stream
            }

            for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
                Instruction instruction = instructionHandle.getInstruction();
                if(!(instruction instanceof InvokeInstruction)) {
                    continue;
                }
                InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;
                boolean tokenVerifyIndications = (tokenInMethodSignature && !foundTokenRequest) || foundGetIdToken;
                if(TOKENREQUEST_VARIATIONS.stream().anyMatch(r -> r.matches(instruction, cpg))) {
                    foundTokenRequest = true;
                } else if(GET_TOKEN_VARIATIONS.stream().anyMatch(r -> r.matches(instruction, cpg))) {
                    foundGetIdToken = true;
                } else if(looksLikeValidTokenSDKVerify(instruction, cpg, tokenVerifyIndications)) {
                    foundTokenVerifyCall = true;
                    methodsWithVerify.add(m);
                } else if(looksLikeManualTokenVerify(methodGen, cpg) && !foundTokenVerifyCall) {
                    foundTokenVerifyCall = true;
                    methodsWithVerify.add(m);
                    methodsRequireAllTokenChecks.add(m);
                } else if(INCOMPLETE_TOKEN_VERIFY_SDK_METHOD.stream().anyMatch(v -> v.matches(instruction, cpg))) {
                   foundIncompleteValidatorSDK = true;
                }

                if(looksLikeIdTokenPassedParam(invokeInstruction, cpg, foundGetIdToken)
                        && foundTokenRequest
                        && !foundTokenPassedAsParamToPossibleCheck
                        && !foundTokenVerifyCall){
                    // FIXME: we must ensure that this looks for something that may do "verify", either by throwing or returning boolean. FP risk: passing on and continuing verify
                    foundTokenPassedAsParamToPossibleCheck = true;

                    boolean calledMethodIndicatesVerify = invokeInstruction.getMethodName(cpg).contains(TOKEN_VARIABLE_NAME_REGEX_PATTERN)
                                                            || invokeInstruction.getMethodName(cpg).matches(VERIFY_REGEXPATTERN);
                    savePassedAsParam(cpg, invokeInstruction,
                                           new AnalyzedMethodPeepholes(
                                                   m,
                                                   foundTokenRequest,
                                                   foundTokenVerifyCall,
                                                   foundTokenPassedAsParamToPossibleCheck,
                                                   foundGetIdToken,
                                                   calledMethodIndicatesVerify
                                           ));
                }
            }

            if(foundIncompleteValidatorSDK) {
                if(!hasVerifyNonce(methodGen, cpg)) {
                    bugReporter.reportBug(new BugInstance(this, USING_INCOMPLETE_ID_TOKEN_VALIDATOR, Priorities.NORMAL_PRIORITY)
                            .addClassAndMethod(javaClass, m));
                    bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_NONCE, Priorities.NORMAL_PRIORITY)
                            .addClassAndMethod(javaClass, m));
                } else if(!hasVerifySignature(methodGen, cpg)) {
                    bugReporter.reportBug(new BugInstance(this, USING_INCOMPLETE_ID_TOKEN_VALIDATOR, Priorities.NORMAL_PRIORITY)
                            .addClassAndMethod(javaClass, m));
                }
            }


            if (foundTokenRequest && !foundTokenVerifyCall && !foundTokenPassedAsParamToPossibleCheck) {
                bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_ID_TOKEN, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }
        }

        if(!methodsRequireAllTokenChecks.isEmpty()) {
            for(Method m: methodsRequireAllTokenChecks) {
                // TODO: for the incomplete libraries it is still okay to use validate() but implementing the additional checks.
                // if using googletokenverifier, check that it still is doing nonce check.
                verifyThatAllChecksAreThere(m, classContext.getMethodGen(m), classContext.getConstantPoolGen());
            }
        }

        if(!methodCallersThatShouldHaveVerify.isEmpty()) {
            for(Method localCalledMethod : methodCallersThatShouldHaveVerify.keySet()) {
                AnalyzedMethodPeepholes analyzedMethod = methodCallersThatShouldHaveVerify.get(localCalledMethod);
                if(analyzedMethod.notClearedAndPossiblyPassesCheck) {
                    if(!methodsWithVerify.contains(localCalledMethod)) {
                        reportInterproceduralMethodCall(javaClass,
                                localCalledMethod,
                                analyzedMethod.method);
                    }
                }
            }
        }


        if(!methodCallersThatShouldHaveCheckForeignMethod.isEmpty()) {
            for(MethodAnnotation calledMethodAnnotation : methodCallersThatShouldHaveCheckForeignMethod.keySet()) {
                AnalyzedMethodPeepholes analyzedMethod = methodCallersThatShouldHaveCheckForeignMethod.get(calledMethodAnnotation);
                if(analyzedMethod.notClearedAndPossiblyPassesCheck && !analyzedMethod.calledMethodNameIndicatesVerify) {
                    reportInterproceduralMethodCall(
                            javaClass,
                            calledMethodAnnotation,
                            analyzedMethod.method
                    );
                }
            }
        }

        if(!methodCallersThatShouldHaveCheckForeignNotFound.isEmpty()) {
            for(CalledMethodIdentifiers calledMethodIdentifiers: methodCallersThatShouldHaveCheckForeignNotFound.keySet()) {
                AnalyzedMethodPeepholes analyzedMethod = methodCallersThatShouldHaveCheckForeignNotFound.get(calledMethodIdentifiers);
                if(analyzedMethod.notClearedAndPossiblyPassesCheck && !analyzedMethod.calledMethodNameIndicatesVerify) {
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
