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
        Map<String, Method> methodCallsThatShouldHaveStateCheck = new HashMap<>(); // Call to a method where state param is called, and caller.
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
            }
        }

        // Search interprocedurally to see whether the called methods actually appear to do verification.
        for (String calledMethodName : methodCallsThatShouldHaveStateCheck.keySet()) {
            Method method = findMethodWithName(javaClass, calledMethodName);
            Method callerMethod = methodCallsThatShouldHaveStateCheck.get(calledMethodName);
            if(method != null && !methodsWithStateCheck.contains(method)) {
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

    @Override
    public void report() {

    }
}




