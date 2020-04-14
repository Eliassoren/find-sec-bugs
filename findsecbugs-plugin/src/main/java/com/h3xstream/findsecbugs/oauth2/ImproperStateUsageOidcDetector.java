package com.h3xstream.findsecbugs.oauth2;

import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import com.h3xstream.findsecbugs.oauth2.data.AnalyzedMethodStateUsage;
import com.h3xstream.findsecbugs.oauth2.data.CalledMethodIdentifiers;
import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Hierarchy;
import edu.umd.cs.findbugs.ba.JavaClassAndMethod;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.*;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class ImproperStateUsageOidcDetector implements Detector {

    // Forget comparing state after receiving response to authorization request.
    // Forget checking state in method reference where state is passed

    private BugReporter bugReporter;
    private static final String FORGOT_VERIFY_OIDC_STATE = "FORGOT_VERIFY_OIDC_STATE";
    private static final String POSSIBLY_FORGOT_VERIFY_OIDC_STATE = "POSSIBLY_FORGOT_VERIFY_OIDC_STATE";
    private static final String POSSIBLY_FORGOT_VERIFY_OIDC_STATE_EXTERNAL_CALL = "POSSIBLY_FORGOT_VERIFY_OIDC_STATE_EXTERNAL_CALL";
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
        boolean foundAuthRequestWithState = false; // This must be true to trigger the search for state verification
        boolean foundStateVerify = false; // This must be true in the end to be safe.
        boolean foundStatePassedAsParamToPossibleCheck = false; // We pass state outside of the procedure and need an additional check.

        Method[] methods = javaClass.getMethods();
        List<Method> methodsWithStateCheck = new ArrayList<>();
        Map<MethodAnnotation, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheckForeignMethod = new HashMap<>();
        Map<CalledMethodIdentifiers, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheckForeignNotFound = new HashMap<>();
        Map<Method, AnalyzedMethodStateUsage> methodCallersThatShouldHaveStateCheck = new HashMap<>();


        // Call to a method where state param is called, and caller.

        for (Method m : methods) {
            foundAuthRequestWithState = false;
            foundStateVerify = false;
            foundStatePassedAsParamToPossibleCheck = false;

            MethodGen methodGen = classContext.getMethodGen(m);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }

            for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
                Instruction instruction = instructionHandle.getInstruction();
                if (instruction instanceof INVOKESPECIAL) {
                    INVOKESPECIAL invoke = (INVOKESPECIAL) instruction;
                    InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;
                    if (AUTH_REQUEST_INIT.matches(instruction, cpg) &&
                            invoke.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/id/State;")) {
                        foundAuthRequestWithState = true;
                    } else if (invoke.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/id/State;") &&
                            // Any other reference where state is passed than AuthenticationResponse assumed to be possible verifier.
                            !invoke.getSignature(cpg).endsWith("Lcom/nimbusds/openid/connect/sdk/AuthenticationRequest;")) {
                        foundStatePassedAsParamToPossibleCheck = true;
                        Method calledMethod = findMethodWithName(javaClass, invoke.getMethodName(cpg));
                        if(calledMethod == null) { // The method called is not in this java class
                            try {
                                JavaClassAndMethod exactMethod = Hierarchy.findExactMethod(invokeInstruction, cpg);
                                MethodAnnotation methodAnnotation = MethodAnnotation.fromXMethod(exactMethod.toXMethod());
                                methodCallersThatShouldHaveStateCheckForeignMethod.put(
                                        methodAnnotation, new AnalyzedMethodStateUsage(m,
                                                                            foundAuthRequestWithState,
                                                                            foundStateVerify,
                                                                            foundStatePassedAsParamToPossibleCheck
                                        ));
                            } catch (ClassNotFoundException e) {
                                CalledMethodIdentifiers calledMethodIdentifiers = new CalledMethodIdentifiers(
                                        invoke.getClassName(cpg),
                                        invoke.getMethodName(cpg),
                                        invoke.getSignature(cpg)
                                );
                                methodCallersThatShouldHaveStateCheckForeignNotFound.put(
                                        calledMethodIdentifiers,
                                        new AnalyzedMethodStateUsage(m,
                                                           foundAuthRequestWithState,
                                                           foundStateVerify,
                                                           foundStatePassedAsParamToPossibleCheck
                                        ));
                            }
                        } else {
                            methodCallersThatShouldHaveStateCheck.put(
                                    calledMethod,
                                    new AnalyzedMethodStateUsage(m,
                                                        foundAuthRequestWithState,
                                                        foundStateVerify,
                                                        foundStatePassedAsParamToPossibleCheck
                                    ));
                        }

                    }
                } else if (instruction instanceof INVOKEVIRTUAL) {
                    if (STATE_EQUALS_METHOD.matches(instruction, cpg)) {
                        foundStateVerify = true;
                        methodsWithStateCheck.add(m);
                    }
                }
            }

            if (foundAuthRequestWithState && !foundStateVerify && !foundStatePassedAsParamToPossibleCheck) {
                bugReporter.reportBug(new BugInstance(this, FORGOT_VERIFY_OIDC_STATE, Priorities.NORMAL_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }
        }


            if(!methodCallersThatShouldHaveStateCheck.isEmpty()) {
                for(Method localCalledMethod : methodCallersThatShouldHaveStateCheck.keySet()) {
                    AnalyzedMethodStateUsage analyzedMethod = methodCallersThatShouldHaveStateCheck.get(localCalledMethod);
                    if(analyzedMethod.foundAuthContextWithState && !analyzedMethod.foundStateVerify && analyzedMethod.foundStatePassedAsParamToPossibleCheck) {
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
                    if(analyzedMethod.foundAuthContextWithState && !analyzedMethod.foundStateVerify && analyzedMethod.foundStatePassedAsParamToPossibleCheck) {
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
                    if(analyzedMethod.foundAuthContextWithState && !analyzedMethod.foundStateVerify && analyzedMethod.foundStatePassedAsParamToPossibleCheck) {
                        reportInterproceduralMethodCall(
                                javaClass,
                                calledMethodIdentifiers,
                                analyzedMethod.method);
                    }
                }
            }
    }

    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 MethodAnnotation lookupCalledMethod,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE_EXTERNAL_CALL, Priorities.LOW_PRIORITY)
            .addClassAndMethod(javaClass, callerMethod)
            .addCalledMethod(lookupCalledMethod.toXMethod()));
    }

    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 Method locallyCalledMethod,
                                                 Method callerMethod) {
        bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE, Priorities.NORMAL_PRIORITY)
                .addClassAndMethod(javaClass, callerMethod));
        bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE, Priorities.NORMAL_PRIORITY)
                .addClassAndMethod(javaClass, locallyCalledMethod));
    }

    private void reportInterproceduralMethodCall(JavaClass javaClass,
                                                 CalledMethodIdentifiers lookupCalledMethodIdentifiers,
                                                 Method callerMethod) {
            bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE_EXTERNAL_CALL, Priorities.NORMAL_PRIORITY)
                    .addClassAndMethod(javaClass, callerMethod)
                    .addString(lookupCalledMethodIdentifiers.toString()));

    }

    private Method findMethodWithName(JavaClass javaClass, String methodName) {
       for(Method m : javaClass.getMethods()) {
           if(methodName.equals(m.getName())) {
               return m;
           }
       }
       return null;
    }

    @Override
    public void report() {

    }
}




