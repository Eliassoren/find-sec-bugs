package com.h3xstream.findsecbugs.oauth2;

import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import com.h3xstream.findsecbugs.oauth2.data.AnalyzedMethod;
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
        boolean foundAuthContext = false; // This must be true to trigger the search for state verification
        boolean foundStateVerify = false; // This must be true in the end to be safe.
        boolean foundStatePassedAsParamToPossibleCheck = false; // We pass state outside of the procedure and need an additional check.

        Method[] methods = javaClass.getMethods();
        List<AnalyzedMethod> analyzedMethods = new ArrayList<>();
        List<Method> methodsWithStateCheck = new ArrayList<>();
        Map<MethodAnnotation, AnalyzedMethod> methodCallersThatShouldHaveStateCheckForeignMethod = new HashMap<>();
        Map<CalledMethodIdentifiers, AnalyzedMethod> methodCallersThatShouldHaveStateCheckForeignNotFound = new HashMap<>();
        Map<Method, AnalyzedMethod> methodCallersThatShouldHaveStateCheck = new HashMap<>();


        // Call to a method where state param is called, and caller.

        for (Method m : methods) {
            foundAuthContext = false;
            foundStateVerify = false;
            foundStatePassedAsParamToPossibleCheck = false;

            MethodGen methodGen = classContext.getMethodGen(m);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }

            for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
                Instruction instruction = instructionHandle.getInstruction();
                InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;
                if (instruction instanceof INVOKESPECIAL) {
                    INVOKESPECIAL invoke = (INVOKESPECIAL) instruction;
                    if (AUTH_REQUEST_INIT.matches(instruction, cpg) &&
                            invoke.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/id/State;")) {
                        foundAuthContext = true;
                    } else if (invoke.getSignature(cpg).contains("Lcom/nimbusds/oauth2/sdk/id/State;") &&
                            // Any other reference where state is passed than AuthenticationResponse assumed to be possible verifier.
                            !invoke.getSignature(cpg).endsWith("Lcom/nimbusds/openid/connect/sdk/AuthenticationResponse;")) {
                        foundStatePassedAsParamToPossibleCheck = true;
                        Method calledMethod = findMethodWithName(javaClass, invoke.getMethodName(cpg));
                        if(calledMethod == null) { // The method called is not in this java class
                            try {
                                JavaClassAndMethod exactMethod = Hierarchy.findExactMethod(invokeInstruction, cpg);
                                MethodAnnotation methodAnnotation = MethodAnnotation.fromXMethod(exactMethod.toXMethod());
                                methodCallersThatShouldHaveStateCheckForeignMethod.put(
                                        methodAnnotation, new AnalyzedMethod(m,
                                                                            foundAuthContext,
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
                                        new AnalyzedMethod(m,
                                                           foundAuthContext,
                                                           foundStateVerify,
                                                           foundStatePassedAsParamToPossibleCheck
                                        ));
                            }
                        } else {
                            methodCallersThatShouldHaveStateCheck.put(
                                    calledMethod,
                                    new AnalyzedMethod(m,
                                                        foundAuthContext,
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

            if (foundAuthContext && !foundStateVerify && !foundStatePassedAsParamToPossibleCheck) {
                bugReporter.reportBug(new BugInstance(this, FORGOT_VERIFY_OIDC_STATE, Priorities.NORMAL_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }
        }

            // FIXME: this is problematic. the variable flags don't correspond since they're reset for each method
            // FIXME: I want to check that we actually have auth context in the given class, and that state verify wasn't found in caller method
            // TODO suggestion: make a data structure with (method, whether it has auth context, whether it constains a state verify)
            // Search interprocedurally to see whether the flagged methods actually appear to do verification.
            //Method method = findMethodWithName(javaClass, calledMethod.getMethodName());
            // hva om method er null? Kallet er til en annen klasse?
            // low
            if(!methodCallersThatShouldHaveStateCheck.isEmpty()) {
                for(Method calledMethod : methodCallersThatShouldHaveStateCheck.keySet()) {
                    AnalyzedMethod analyzedMethod = methodCallersThatShouldHaveStateCheck.get(calledMethod);
                    if(analyzedMethod.foundAuthContext && !analyzedMethod.foundStateVerify && analyzedMethod.foundStatePassedAsParamToPossibleCheck) {
                        reportInterproceduralMethodCall(javaClass,
                                                    calledMethod,
                                                    analyzedMethod.method,
                                                    methodsWithStateCheck);
                    }
                }
            }

            if(!methodCallersThatShouldHaveStateCheckForeignMethod.isEmpty()) {
                for(MethodAnnotation calledMethodAnnotation : methodCallersThatShouldHaveStateCheckForeignMethod.keySet()) {
                    AnalyzedMethod analyzedMethod = methodCallersThatShouldHaveStateCheckForeignMethod.get(calledMethodAnnotation);
                    if(analyzedMethod.foundAuthContext && !analyzedMethod.foundStateVerify && analyzedMethod.foundStatePassedAsParamToPossibleCheck) {
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
                    AnalyzedMethod analyzedMethod = methodCallersThatShouldHaveStateCheckForeignNotFound.get(calledMethodIdentifiers);
                    if(analyzedMethod.foundAuthContext && !analyzedMethod.foundStateVerify && analyzedMethod.foundStatePassedAsParamToPossibleCheck) {
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
                                                 Method lookupCalledMethod,
                                                 Method callerMethod,
                                                 List<Method> methodsWithStateCheck) {


        if(!methodsWithStateCheck.contains(lookupCalledMethod)) {
            bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE, Priorities.NORMAL_PRIORITY)
                    .addClassAndMethod(javaClass, callerMethod));
            bugReporter.reportBug(new BugInstance(this, POSSIBLY_FORGOT_VERIFY_OIDC_STATE, Priorities.NORMAL_PRIORITY)
                    .addClassAndMethod(javaClass, lookupCalledMethod));
        }
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




