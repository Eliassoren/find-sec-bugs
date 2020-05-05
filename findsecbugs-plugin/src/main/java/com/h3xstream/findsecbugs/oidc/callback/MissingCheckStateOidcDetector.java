package com.h3xstream.findsecbugs.oidc.callback;

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

public class MissingCheckStateOidcDetector implements Detector {
    private final BugReporter bugReporter;
    private static final String MISSING_VERIFY_OIDC_STATE = "MISSING_VERIFY_OIDC_STATE";
    private static final String EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE = "EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE";
    // TODO: Add scenario for FP reduction: if the externaly called method is explicitly names "verifyState" or something obvious, allow it.
    // Or make an additional warning class just informing...

    private Map<MethodAnnotation, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheckForeignMethod = new HashMap<>();
    private Map<CalledMethodIdentifiers, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheckForeignNotFound = new HashMap<>();
    private Map<Method, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheck = new HashMap<>();
    JavaClass javaClass;
    private static final InvokeMatcherBuilder
            AUTH_RESPONSE_PARSE = invokeInstruction()
            .atClass("com/nimbusds/openid/connect/sdk/AuthenticationResponseParser")
            .atMethod("parse")
            .withArgs("(Ljava/net/URI;)Lcom/nimbusds/openid/connect/sdk/AuthenticationResponse;");

    private static final InvokeMatcherBuilder
            AUTH_RESPONSE_PARSE_GOOGLE = invokeInstruction()
            .atClass("com/google/api/client/auth/oauth2/AuthorizationCodeResponseUrl")
            .atMethod("<init>")
            .withArgs("(Ljava/lang/String;)V");// TODO: generalize statement. This trigger should be configurable

    private static final InvokeMatcherBuilder
            GET_STATE_METHOD = invokeInstruction()
            .atClass("com/nimbusds/openid/connect/sdk/AuthenticationResponse",
                    "com/google/api/client/auth/oauth2/AuthorizationCodeResponseUrl")
            .atMethod("getState");

    private static final InvokeMatcherBuilder
            STATE_EQUALS_METHOD = invokeInstruction() //
            .atClass("com/nimbusds/oauth2/sdk/id/State")
            .atMethod("equals")
            .withArgs("(Ljava/lang/Object;)Z"); // TODO: generalize. More params should be checked. In Googleapi, strings are used. May want to evaluate for certain variable names to be sure.

    private static final InvokeMatcherBuilder
            STRING_EQUALS_METHOD = invokeInstruction() //
            .atClass("java/lang/String")
            .atMethod("equals")
            .withArgs("(Ljava/lang/Object;)Z");
    private static final String STATE_VARIABLE_NAME_REGEX = "state"; // TODO: add possible variations

    private static final List<InvokeMatcherBuilder> AUTH_RESPONSE_PARSE_VARIATIONS = Arrays.asList(
                                                                        AUTH_RESPONSE_PARSE,
                                                                        AUTH_RESPONSE_PARSE_GOOGLE
                                                                        );


    private static final List<InvokeMatcherBuilder> STATE_EQUALS_INVOKE_VARIATIONS = Arrays.asList(
                                                                        STATE_EQUALS_METHOD
                                                                        );

    private boolean looksLikeStateVerify(Instruction instruction, ConstantPoolGen cpg, boolean indicationsOfStateVar) {
        return (STATE_EQUALS_INVOKE_VARIATIONS.stream().anyMatch(i -> i.matches(instruction, cpg))) // Tightly defined state type
                || (STRING_EQUALS_METHOD.matches(instruction, cpg) && indicationsOfStateVar); // String with name
    }

    private boolean looksLikeStatePassedParam(InvokeInstruction invokeInstruction, ConstantPoolGen cpg, boolean foundGetState) {
        boolean stateParameter = (invokeInstruction.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/id/State;") // TODO: pass to "lookLikePassedAsParam" and generalize
                && !invokeInstruction.getSignature(cpg).endsWith("Lcom/nimbusds/oauth2/sdk/id/State;"))
                || (invokeInstruction.getSignature(cpg).contains("Ljava/lang/String;") && foundGetState);
        boolean isAuthenticationRequest =  invokeInstruction.getSignature(cpg).endsWith("Lcom/nimbusds/openid/connect/sdk/AuthenticationRequest;")
                || invokeInstruction.getSignature(cpg).endsWith("Lcom/google/api/client/auth/oauth2/AuthorizationCodeRequestUrl;"); // todo: collection of auth request signatures
        boolean returnTypeSeemsLikeVerifyFunction = (invokeInstruction.getReturnType(cpg).equals(Type.BOOLEAN)
                || invokeInstruction.getReturnType(cpg).equals(Type.VOID));
        return stateParameter && !isAuthenticationRequest && returnTypeSeemsLikeVerifyFunction;
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

    public MissingCheckStateOidcDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {

        javaClass = classContext.getJavaClass();
        boolean foundAuthResponseParse = false; // This must be true to trigger the search for state verification
        boolean foundStateVerify = false; // This must be true in the end to be safe.
        boolean foundStatePassedAsParamToPossibleCheck = false; // We pass state outside of the procedure and need an additional check.
        boolean foundGetState = false; //method based on callback response Method com/google/api/client/auth/oauth2/AuthorizationCodeResponseUrl.getState:()Ljava/lang/String;
        boolean stateInMethodName = false;
        
        Method[] methods = javaClass.getMethods();
        List<Method> methodsWithStateCheck = new ArrayList<>();
        methodCallersThatShouldHaveStateCheckForeignMethod = new HashMap<>();
        methodCallersThatShouldHaveStateCheckForeignNotFound = new HashMap<>();
        methodCallersThatShouldHaveStateCheck = new HashMap<>();

        // Call to a method where state param is called, and caller.

        for (Method m : methods) {
            foundAuthResponseParse = false;
            foundStateVerify = false;
            foundStatePassedAsParamToPossibleCheck = false;
            foundGetState = false;
            stateInMethodName = false;

            MethodGen methodGen = classContext.getMethodGen(m);

            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }
            if(methodGen.getName().toLowerCase().contains("state")
                    || Arrays.stream(m.getLocalVariableTable()
                            .getLocalVariableTable())
                            .anyMatch(name -> name.getName().matches(STATE_VARIABLE_NAME_REGEX)
                                    || name.getSignature().contains("Lcom/nimbusds/oauth2/sdk/id/State;"))) {
                // Localvariabletable

                stateInMethodName = true;
            }

            for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
                Instruction instruction = instructionHandle.getInstruction();
                if(!(instruction instanceof InvokeInstruction)) {
                    continue;
                }
                InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;
                boolean stateVerifyMethodIndications = stateInMethodName && !foundAuthResponseParse; // Probably a verify method
                if(AUTH_RESPONSE_PARSE_VARIATIONS.stream().anyMatch(i -> i.matches(instruction, cpg))) {
                    foundAuthResponseParse = true;
                } else if(GET_STATE_METHOD.matches(instruction, cpg)) {
                    foundGetState = true;
                } else if(looksLikeStateVerify(instruction, cpg, foundGetState || stateVerifyMethodIndications)) {
                    foundStateVerify = true;
                    methodsWithStateCheck.add(m);
                }

               if(looksLikeStatePassedParam(invokeInstruction, cpg, foundGetState)
                       && foundAuthResponseParse
                       && !foundStatePassedAsParamToPossibleCheck
                       && !foundStateVerify){
                   // FIXME: we must ensure that this looks for something that may do "verify", either by throwing or returning boolean. FP risk: passing on and continuing verify
                    // TODO: look at logic. Null now.
                   foundStatePassedAsParamToPossibleCheck = true;


                   boolean calledMethodContainsStateInName = invokeInstruction.getMethodName(cpg).contains("state");
                   saveStatePassedAsParam(cpg, invokeInstruction,
                           new AnalyzedMethodStateUsage(m,
                           foundAuthResponseParse,
                           foundStateVerify,
                           true,
                           foundGetState,
                           calledMethodContainsStateInName
                   ));
                }
            }

            if (foundAuthResponseParse && !foundStateVerify && !foundStatePassedAsParamToPossibleCheck) {
                bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_OIDC_STATE, Priorities.HIGH_PRIORITY)
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
        bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_OIDC_STATE, Priorities.HIGH_PRIORITY)
                .addClassAndMethod(javaClass, callerMethod));
        bugReporter.reportBug(new BugInstance(this, MISSING_VERIFY_OIDC_STATE, Priorities.HIGH_PRIORITY)
                .addClassAndMethod(javaClass, locallyCalledMethod));
    }

    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 MethodAnnotation lookupCalledMethod,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE, Priorities.LOW_PRIORITY)
                .addClassAndMethod(javaClass, callerMethod)
                .addCalledMethod(lookupCalledMethod.toXMethod()));
    }


    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 CalledMethodIdentifiers lookupCalledMethodIdentifiers,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, EXTERNAL_CALL_POSSIBLY_MISSING_VERIFY_OIDC_STATE, Priorities.LOW_PRIORITY)
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
