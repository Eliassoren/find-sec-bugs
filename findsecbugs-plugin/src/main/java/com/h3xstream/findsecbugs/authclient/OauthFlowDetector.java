package com.h3xstream.findsecbugs.authclient;

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.ClassContext;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.util.Iterator;

public class OauthFlowDetector implements Detector {
    private static final String AUTHCLIENT_TEST_RANDOMNUMBER = "AUTHCLIENT_TEST_RANDOMNUMBER";
    private BugReporter bugReporter;

    @Override
    public void visitClassContext(ClassContext classContext) {
        JavaClass javaClass = classContext.getJavaClass();

        Method[] methods = javaClass.getMethods();

        for(Method m : methods) {
            boolean invokeRandomNumber = false;

            MethodGen methodGen = classContext.getMethodGen(m);

            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }
            for (InstructionHandle instructionHandle : methodGen.getInstructionList()) {
                Instruction inst = instructionHandle.getInstruction();
                if (inst instanceof INVOKEVIRTUAL) {
                    INVOKEVIRTUAL invokevirtual = (INVOKEVIRTUAL) inst;
                    if ("SecureRandom".equals(invokevirtual.getClassName(cpg)) && "nextInt".equals(invokevirtual.getMethodName(cpg))) {
                        invokeRandomNumber = true;
                    }
                }
            }
            if (invokeRandomNumber) {
                bugReporter.reportBug(new BugInstance(
                        this,
                        AUTHCLIENT_TEST_RANDOMNUMBER,
                        Priorities.LOW_PRIORITY)
                        .addClassAndMethod(javaClass, m));
            }
        }
    }

    @Override
    public void report() {

    }
}
