package com.h3xstream.findsecbugs.authclient;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.ClassContext;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

public class SecureRandomTestDetector implements Detector {
    private static final String TEST_USING_SECURE_RANDOM = "TEST_USING_SECURE_RANDOM";
    private BugReporter bugReporter;

    public SecureRandomTestDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void visitClassContext(ClassContext classContext) {
        JavaClass javaClass = classContext.getJavaClass();

        Method[] methods = javaClass.getMethods();
        if(javaClass.getClassName().contains("testcode.authclient.AuthTestCases") ||
                javaClass.getClassName().contains("AuthTestCases")) return; // avoid conflict

        for(Method m : methods) {
            MethodGen methodGen = classContext.getMethodGen(m);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }
            if (secureRandomNumberUsage(methodGen, cpg)) {
                bugReporter.reportBug(new BugInstance(
                        this,
                        TEST_USING_SECURE_RANDOM,
                        Priorities.LOW_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }
        }
    }

    private boolean secureRandomNumberUsage(MethodGen methodGen,  ConstantPoolGen cpg) {
        for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
            Instruction inst = instructionHandle.getInstruction();
            if (inst instanceof INVOKEVIRTUAL) {
                INVOKEVIRTUAL invokevirtual = (INVOKEVIRTUAL) inst;
                if ("java.security.SecureRandom".equals(invokevirtual.getClassName(cpg)) && "nextInt".equals(invokevirtual.getMethodName(cpg))) {
                    return true;
                }
            }
        }
        return false;
    }


    @Override
    public void report() {

    }
}
