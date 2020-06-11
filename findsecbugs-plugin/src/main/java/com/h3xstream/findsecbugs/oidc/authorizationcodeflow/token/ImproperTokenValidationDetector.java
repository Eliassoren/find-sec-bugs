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
import java.util.regex.Pattern;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class ImproperTokenValidationDetector implements Detector {
    private final BugReporter bugReporter;
    private static final String MISSING_VERIFY_ID_TOKEN = "MISSING_VERIFY_ID_TOKEN"; // Collector if all five checks missing
    private static final String INCOMPLETE_ID_TOKEN_VERIFICATION = "INCOMPLETE_ID_TOKEN_VERIFICATION"; // Collector warning if less than 5 but more than 0 checks are missing

    private static final String EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN = "EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN";
    private static final String MISSING_VERIFY_NONCE = "MISSING_VERIFY_NONCE";
    private static final String MISSING_VERIFY_TOKEN_ISS = "MISSING_VERIFY_TOKEN_ISS";
    private static final String MISSING_VERIFY_TOKEN_AUD = "MISSING_VERIFY_TOKEN_AUD";
    private static final String MISSING_VERIFY_TOKEN_SIGN = "MISSING_VERIFY_TOKEN_SIGN";
    private static final String MISSING_VERIFY_TOKEN_EXP = "MISSING_VERIFY_TOKEN_EXP";


    private static final String USING_INCOMPLETE_ID_TOKEN_VALIDATOR = "USING_INCOMPLETE_ID_TOKEN_VALIDATOR";





    private List<String> missingTokenChecks;

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
            GET_ID_TOKEN_GOOGLE = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdTokenResponse")
            .atMethod("getIdToken");

    private static final InvokeMatcherBuilder
        GET_ID_TOKEN_NIMBUS = invokeInstruction()
            .atClass("com/nimbusds/openid/connect/sdk/token/OIDCTokens")
            .atMethod("getIDToken")
            .withArgs("()Lcom/nimbusds/jwt/JWT;");

    private static final List<InvokeMatcherBuilder> GET_TOKEN_VARIATIONS = Arrays.asList(
            PARSE_ID_TOKEN_GOOGLE,
            GET_ID_TOKEN_GOOGLE,
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
            GOOGLE_VERIFY_AUD_SDK = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdTokenVerifier$Builder")
            .atMethod("setAudience");
    private static final InvokeMatcherBuilder
            GOOGLE_VERIFY_ISS_SDK = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdTokenVerifier$Builder")
            .atMethod("setIssuer");
    private static final InvokeMatcherBuilder
            GOOGLE_VERIFY_EXP_SDK = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdTokenVerifier$Builder")
            .atMethod("setAcceptableTimeSkewSeconds");

    private static final InvokeMatcherBuilder
            GOOGLE_INTERNAL_TOKEN_VERIFY_SDK = invokeInstruction() // missing nonce check but has crypto
            .atClass("com/google/api/client/auth/openidconnect/IdTokenVerifier") // fixme: change to GoogleIdTokenVerifier, or whatever is the value in the google client
            .atMethod("verify")
            .withArgs("(Lcom/google/api/client/auth/openidconnect/IdToken;)Z");


    private static final String TOKEN_VARIABLE_NAME_REGEX_PATTERN = ".*token|Token.*"; // TODO: add possible variations
    private static final String VERIFY_REGEXPATTERN = ".*verify|Verify|valid|Valid.*"; // TODO: add possible variations
    private static final String NONCE_REGEXPATTERN = ".*nonce|Nonce.*"; // TODO: add possible variations
    private static final String ISSUER_REGEXPATTERN = ".*iss|Iss|issuer|Issuer.*"; // TODO: add possible variations
    private static final String SIGNATURE_REGEXPATTERN = ".*sign|Sign|signature|Signature.*"; // TODO: add possible variations
    private static final String AUD_REGEXPATTERN = ".*aud|Aud|audience|Audience.*"; // TODO: add possible variations
    private static final String TIME_REGEXPATTERN = ".*time|Time|exp|Exp|iat|Iat|issuedAtTime.*"; // TODO: add possible variations

    private static final List<String> idTokenParameterNameRegex = Arrays.asList(
    ISSUER_REGEXPATTERN,
    AUD_REGEXPATTERN,
    NONCE_REGEXPATTERN,
    TIME_REGEXPATTERN,
    SIGNATURE_REGEXPATTERN
    );
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
            .atMethod("verifyIssuer");

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
            GOOGLE_VERIFY_ISS_SDK,
            GOOGLE_VERIFY_AUD,
            GOOGLE_VERIFY_AUD_SDK,
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
            if(TOKEN_VERIFY_REQUIRED_CHECKS.stream().anyMatch(c -> {
                missingTokenChecks.remove(c);
                return c.matches(instruction, cpg);
            })) {
                foundTokenVerifyMethod = true;
            }
        }
        return foundTokenVerifyMethod || hasVerifyNonce(methodGen, cpg);
    }

    private void addMethodToListNoDuplicates(Method method, List<Method> methods) {
        if(!methods.contains(method)) {
            methods.add(method);
        }
    }

    private boolean looksLikeValidTokenSDKVerify(Instruction instruction, ConstantPoolGen cpg, boolean indicationsOfVariableToVerify) {
        return (TOKEN_VERIFY_SDK_VARIATIONS.stream().anyMatch(i -> i.matches(instruction, cpg)));
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

    private boolean verifyThatAllChecksAreThere(Method m, MethodGen methodGen, ConstantPoolGen cpg) {
        boolean foundVerifyIss = false;
        boolean foundVerifyAud = false;
        boolean foundVerifySignatureCrypto = false;
        boolean foundVerifyNonce = false;
        boolean foundVerifyExp = false;

        if (methodGen == null || methodGen.getInstructionList() == null) {
            return false; //No instruction .. nothing to do
        }
        for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
            Instruction instruction = instructionHandle.getInstruction();
            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            if(GOOGLE_VERIFY_ISSUER.matches(instruction, cpg) || GOOGLE_VERIFY_ISS_SDK.matches(instruction, cpg)) {
                foundVerifyIss = true;
                missingTokenChecks.remove(MISSING_VERIFY_TOKEN_ISS);
            } else if(GOOGLE_VERIFY_AUD.matches(instruction, cpg) || GOOGLE_VERIFY_AUD_SDK.matches(instruction, cpg)) {
                foundVerifyAud = true;
                missingTokenChecks.remove(MISSING_VERIFY_TOKEN_AUD);
            } else if(GOOGLE_VERIFY_SIGNATURE.matches(instruction, cpg)) {
                foundVerifySignatureCrypto = true;
                missingTokenChecks.remove(MISSING_VERIFY_TOKEN_SIGN);
            } else if(GOOGLE_VERIFY_EXP.matches(instruction, cpg)
                    || GOOGLE_VERIFY_EXP_SDK.matches(instruction, cpg)
                    || GOOGLE_TOKEN_VERIFY_SDK.matches(instruction, cpg) ) {
                missingTokenChecks.remove(MISSING_VERIFY_TOKEN_EXP);
                foundVerifyExp = true;
            }
        }

        foundVerifyNonce = hasVerifyNonce(methodGen, cpg);
        if(foundVerifyNonce) {
            missingTokenChecks.remove(MISSING_VERIFY_NONCE);
        }
        boolean completeVerify = foundVerifyIss
                                && foundVerifyAud
                                && foundVerifySignatureCrypto
                                && foundVerifyExp
                                && foundVerifyNonce;

        if(!completeVerify) {
            bugReporter.reportBug(new BugInstance(this, INCOMPLETE_ID_TOKEN_VERIFICATION, Priorities.NORMAL_PRIORITY)
                    .addClassAndMethod(javaClass, m));
            for (String MISSING_TOKEN_CHECK : missingTokenChecks) {
                bugReporter.reportBug(new BugInstance(this, MISSING_TOKEN_CHECK, Priorities.NORMAL_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }
        }
        return completeVerify;
    }

    private void removeAnyMatchingCheck(MethodGen methodGen, ConstantPoolGen cpg) {
        if (methodGen == null || methodGen.getInstructionList() == null) {
            return; //No instruction .. nothing to do
        }
        for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
            Instruction instruction = instructionHandle.getInstruction();
            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            if(GOOGLE_VERIFY_ISSUER.matches(instruction, cpg) || GOOGLE_VERIFY_ISS_SDK.matches(instruction, cpg)) {
                missingTokenChecks.remove(MISSING_VERIFY_TOKEN_ISS);
            } else if(GOOGLE_VERIFY_AUD.matches(instruction, cpg) || GOOGLE_VERIFY_AUD_SDK.matches(instruction, cpg)) {
                missingTokenChecks.remove(MISSING_VERIFY_TOKEN_AUD);
            } else if(GOOGLE_VERIFY_SIGNATURE.matches(instruction, cpg)) {
                missingTokenChecks.remove(MISSING_VERIFY_TOKEN_SIGN);
            } else if(GOOGLE_VERIFY_EXP.matches(instruction, cpg)
                    || GOOGLE_VERIFY_EXP_SDK.matches(instruction, cpg)
                    || GOOGLE_TOKEN_VERIFY_SDK.matches(instruction, cpg) ) {
                missingTokenChecks.remove(MISSING_VERIFY_TOKEN_EXP);
            }
        }
        if(hasVerifyNonce(methodGen, cpg)) {
            missingTokenChecks.remove(MISSING_VERIFY_NONCE);
        }
    }

    private boolean looksLikeStringPassedAsParamToMethod(InvokeInstruction invokeInstruction, ConstantPoolGen cpg) {
        return (invokeInstruction.getSignature(cpg).contains("Ljava/lang/String;")
                && (!invokeInstruction.getSignature(cpg).endsWith("Ljava/lang/String;") ||
                invokeInstruction.getReturnType(cpg).equals(Type.VOID) || invokeInstruction.getReturnType(cpg).equals(Type.BOOLEAN)));
    }

    private boolean looksLikeIdTokenPassedParam(InvokeInstruction invokeInstruction, ConstantPoolGen cpg, boolean foundGetState) {
        // OK_validateToken:(Ltestcode/oidc/util/nimbus/OidcConfig;Lcom/nimbusds/oauth2/sdk/TokenResponse;)Ljavax/ws/rs/core/Response;
        //  // Method OK_validateTokenVoid:(Ltestcode/oidc/util/nimbus/OidcConfig;Lcom/nimbusds/oauth2/sdk/TokenResponse;)V
        boolean idTokenParameterNimbus =
                ((invokeInstruction.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/TokenResponse;")
                        || (invokeInstruction.getSignature(cpg).contains("Lcom/nimbusds/openid/connect/sdk/OIDCTokenResponse;"))
                         &&
                        ((!invokeInstruction.getSignature(cpg).endsWith("Lcom/nimbusds/oauth2/sdk/TokenResponse;")
                         || (!invokeInstruction.getSignature(cpg).endsWith("Lcom/nimbusds/openid/connect/sdk/OIDCTokenResponse;")))
                         || invokeInstruction.getReturnType(cpg).equals(Type.VOID)
                         || invokeInstruction.getReturnType(cpg).equals(Type.BOOLEAN))
                        )
                        || (invokeInstruction.getSignature(cpg).contains("Lcom/nimbusds/jwt/JWT;")
                         && (!invokeInstruction.getSignature(cpg).endsWith("Lcom/nimbusds/jwt/JWT;")
                         || invokeInstruction.getReturnType(cpg).equals(Type.VOID)
                         || invokeInstruction.getReturnType(cpg).equals(Type.BOOLEAN))));
                 // Google SDK
         boolean idTokenParameterGoogle =  (invokeInstruction.getSignature(cpg).contains("Lcom/google/api/client/auth/openidconnect/IdTokenResponse;") // google
                        && (!invokeInstruction.getSignature(cpg).endsWith("Lcom/google/api/client/auth/openidconnect/IdTokenResponse;") ||
                 invokeInstruction.getReturnType(cpg).equals(Type.VOID) || invokeInstruction.getReturnType(cpg).equals(Type.BOOLEAN)))
               || (invokeInstruction.getSignature(cpg).contains("Lcom/google/api/client/auth/openidconnect/IdToken;")
                        && (!invokeInstruction.getSignature(cpg).endsWith("Lcom/google/api/client/auth/openidconnect/IdToken;")||
                 invokeInstruction.getReturnType(cpg).equals(Type.VOID) || invokeInstruction.getReturnType(cpg).equals(Type.BOOLEAN)));
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
        boolean isThisAVerifyMethod = false;
        Method[] methods = javaClass.getMethods();
        List<Method> methodsWithVerify = new ArrayList<>();
        List<Method> methodsRequireAllTokenChecks = new ArrayList<>();
        methodCallersThatShouldHaveCheckForeignMethod = new HashMap<>();
        methodCallersThatShouldHaveCheckForeignNotFound = new HashMap<>();
        methodCallersThatShouldHaveVerify = new HashMap<>();
        missingTokenChecks = new ArrayList<>(Arrays.asList(
                MISSING_VERIFY_NONCE,
                MISSING_VERIFY_TOKEN_ISS,
                MISSING_VERIFY_TOKEN_AUD,
                MISSING_VERIFY_TOKEN_SIGN,
                MISSING_VERIFY_TOKEN_EXP
        ));

        // Call to a method where state param is called, and caller.

        for (Method m : methods) {
            foundTokenPassedAsParamToPossibleCheck = false;
            foundGetIdToken = false;
            foundTokenRequest = false;
            foundTokenVerifyCall = false;
            tokenInMethodSignature = false;
            isThisAVerifyMethod = false;
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

                boolean idTokenVariableMatchMethodName = idTokenParameterNameRegex.stream().anyMatch(r ->
                    Pattern.compile(r).matcher(methodGen.getName().toLowerCase()).find()
                );
                boolean verifyRegexMatchMethodName = Pattern.compile(VERIFY_REGEXPATTERN).matcher(methodGen.getName().toLowerCase()).find();
                if (idTokenVariableMatchMethodName && verifyRegexMatchMethodName) {
                    // Localvariabletable
                    isThisAVerifyMethod = true;
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
                boolean calledMethodIndicatesVerify = Pattern.compile(TOKEN_VARIABLE_NAME_REGEX_PATTERN).matcher(invokeInstruction.getMethodName(cpg)).find()
                        || Pattern.compile(VERIFY_REGEXPATTERN).matcher(invokeInstruction.getMethodName(cpg)).find();
                boolean tokenVerifyIndications = (tokenInMethodSignature && !foundTokenRequest) || foundGetIdToken;
                removeAnyMatchingCheck(methodGen, cpg);
                if(TOKENREQUEST_VARIATIONS.stream().anyMatch(r -> r.matches(instruction, cpg))) {
                    foundTokenRequest = true;
                } else if(GET_TOKEN_VARIATIONS.stream().anyMatch(r -> r.matches(instruction, cpg))) {
                    foundGetIdToken = true;
                } else if(looksLikeValidTokenSDKVerify(instruction, cpg, tokenVerifyIndications)) {
                    foundTokenVerifyCall = true;
                    addMethodToListNoDuplicates(m, methodsWithVerify);
                } else if(looksLikeManualTokenVerify(methodGen, cpg) && !foundTokenVerifyCall && !isThisAVerifyMethod) {
                    foundTokenVerifyCall = true;
                    addMethodToListNoDuplicates(m, methodsWithVerify);
                    addMethodToListNoDuplicates(m, methodsRequireAllTokenChecks);
                } else if(INCOMPLETE_TOKEN_VERIFY_SDK_METHOD.stream().anyMatch(v -> v.matches(instruction, cpg))) {
                    foundIncompleteValidatorSDK = true;
                    foundTokenVerifyCall = true;
                    addMethodToListNoDuplicates(m, methodsRequireAllTokenChecks);
                }

                if((looksLikeIdTokenPassedParam(invokeInstruction, cpg, foundGetIdToken) && calledMethodIndicatesVerify)
                        && (foundTokenRequest || foundGetIdToken)
                        && !foundTokenPassedAsParamToPossibleCheck
                        && !foundTokenVerifyCall){
                    // FIXME: we must ensure that this looks for something that may do "verify", either by throwing or returning boolean. FP risk: passing on and continuing verify
                    foundTokenPassedAsParamToPossibleCheck = true;

                    savePassedAsParam(cpg, invokeInstruction,
                                           new AnalyzedMethodPeepholes(
                                                   m,
                                                   foundTokenRequest,
                                                   foundTokenVerifyCall,
                                                   foundTokenPassedAsParamToPossibleCheck,
                                                   foundGetIdToken,
                                                   calledMethodIndicatesVerify
                                           ));
                } else if(foundGetIdToken &&
                            looksLikeStringPassedAsParamToMethod(invokeInstruction, cpg)
                            && calledMethodIndicatesVerify) {
                    foundTokenPassedAsParamToPossibleCheck = true;
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

            if ((foundTokenRequest || foundGetIdToken) && !foundTokenVerifyCall && !foundTokenPassedAsParamToPossibleCheck) {
                bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_ID_TOKEN, Priorities.HIGH_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }

            if(foundIncompleteValidatorSDK) {
                if( !verifyThatAllChecksAreThere(m, methodGen, cpg)) {
                    bugReporter.reportBug(new BugInstance(this, USING_INCOMPLETE_ID_TOKEN_VALIDATOR, Priorities.NORMAL_PRIORITY)
                            .addClassAndMethod(javaClass, m));
                }
                methodsRequireAllTokenChecks.remove(m);
            }
        }

        if(!methodsRequireAllTokenChecks.isEmpty()) {
            for(Method m: methodsRequireAllTokenChecks) {
                verifyThatAllChecksAreThere(m, classContext.getMethodGen(m), classContext.getConstantPoolGen());
            }
        }

        if(!methodCallersThatShouldHaveVerify.isEmpty()) {
            for(Method localCalledMethod : methodCallersThatShouldHaveVerify.keySet()) {
                AnalyzedMethodPeepholes analyzedMethod = methodCallersThatShouldHaveVerify.get(localCalledMethod);
                if(analyzedMethod.notClearedAndPossiblyPassesCheck) {
                    if(!methodsWithVerify.contains(localCalledMethod)) {
                        if(analyzedMethod.calledMethodNameIndicatesVerify) {
                            reportInterproceduralMethodCallIncomplete(javaClass,
                                    localCalledMethod,
                                    analyzedMethod.method);
                        } else {
                            reportInterproceduralMethodCall(javaClass,
                                    localCalledMethod,
                                    analyzedMethod.method);
                        }
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

    private void reportInterproceduralMethodCallIncomplete(JavaClass javaClass,
                                                 Method locallyCalledMethod,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, INCOMPLETE_ID_TOKEN_VERIFICATION, Priorities.HIGH_PRIORITY)
                .addClassAndMethod(javaClass, callerMethod));
        //bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_ID_TOKEN, Priorities.HIGH_PRIORITY)
          //      .addClassAndMethod(javaClass, locallyCalledMethod));
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
        bugReporter.reportBug(new BugInstance(this, EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN, Priorities.NORMAL_PRIORITY)
                .addClassAndMethod(javaClass, callerMethod)
                .addCalledMethod(lookupCalledMethod.toXMethod()));
    }


    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 CalledMethodIdentifiers lookupCalledMethodIdentifiers,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_ID_TOKEN, Priorities.NORMAL_PRIORITY)
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