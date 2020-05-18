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
package com.h3xstream.findsecbugs.oidc;

import edu.umd.cs.findbugs.*;
import edu.umd.cs.findbugs.ba.*;
import edu.umd.cs.findbugs.ba.npe.IsNullValue;
import edu.umd.cs.findbugs.ba.npe.IsNullValueDataflow;
import edu.umd.cs.findbugs.ba.npe.IsNullValueFrame;
import edu.umd.cs.findbugs.ba.type.ExceptionSetFactory;
import edu.umd.cs.findbugs.ba.type.StandardTypeMerger;
import edu.umd.cs.findbugs.ba.vna.ValueNumber;
import edu.umd.cs.findbugs.ba.vna.ValueNumberDataflow;
import edu.umd.cs.findbugs.ba.vna.ValueNumberFrame;
import edu.umd.cs.findbugs.bcel.BCELUtil;
import edu.umd.cs.findbugs.classfile.CheckedAnalysisException;
import edu.umd.cs.findbugs.classfile.Global;
import edu.umd.cs.findbugs.classfile.IAnalysisCache;
import edu.umd.cs.findbugs.classfile.MethodDescriptor;
import edu.umd.cs.findbugs.util.ClassName;
import org.apache.bcel.Const;
import org.apache.bcel.classfile.*;
import org.apache.bcel.generic.*;

import java.util.BitSet;

class Secret extends ResourceCreationPoint {
    private final ValueNumber secretValue;

    public Secret(Location location, String secretClass, ValueNumber secretValue) {
        super(location, secretClass);
        this.secretValue = secretValue;
    }

    public ValueNumber getSecretValue() {
        return secretValue;
    }
}

class SecretValueFrame extends ResourceValueFrame {
    public static final int OPEN_IN_TRY_CATCH = 6;
    private int status = 5;
    private static final String[] statusList = new String[]{"(escaped)", "(open)", "(open_exception)", "(closed)", "(created)", "(nonexistent)", "(open_trycatch)"};
    public SecretValueFrame(int numSlots) {
        super(numSlots);
    }
}

public class InsecureDeleteSecretDetector extends ResourceTrackingDetector<Secret, InsecureDeleteSecretDetector.SecretResourceTracker> {


    private static final boolean DEBUG = SystemProperties.getBoolean("ful.debug");

    private int numAcquires = 0;



    private static class SecretFrameModelingVisitor extends ResourceValueFrameModelingVisitor {
        private final SecretResourceTracker resourceTracker;

        private final Secret secret;

        private final ValueNumberDataflow vnaDataflow;


        // private IsNullValueDataflow isNullDataflow;

        public SecretFrameModelingVisitor(ConstantPoolGen cpg, SecretResourceTracker resourceTracker, Secret secret,
                                          ValueNumberDataflow valueNumberDataflow, IsNullValueDataflow isNullDataflow) {
            super(cpg);
            this.resourceTracker = resourceTracker;
            this.secret = secret;
            this.vnaDataflow = valueNumberDataflow;

            // this.isNullDataflow = isNullDataflow;
        }

        @Override
        public void transferInstruction(InstructionHandle handle, BasicBlock basicBlock) throws DataflowAnalysisException {
            final Instruction ins = handle.getInstruction();
            final ConstantPoolGen cpg = getCPG();
            final ResourceValueFrame frame = getFrame();

            int status = -1;

            if (DEBUG) {
                System.out.println("PC : " + handle.getPosition() + " " + ins);
            }
            if (DEBUG && ins instanceof InvokeInstruction) {
                System.out.println("  " + ins.toString(cpg.getConstantPool()));
            }
            if (DEBUG) {
                System.out.println("resource frame before instruction: " + frame.toString());
            }

            // Is a secret acquired or released by this instruction?
            Location creationPoint = secret.getLocation();
            if (handle == creationPoint.getHandle() && basicBlock == creationPoint.getBasicBlock()) {
                status = ResourceValueFrame.OPEN;
                if (DEBUG) {
                    System.out.println("OPEN");
                }
            }
            else if (resourceTracker.isResourceClose(basicBlock, handle, cpg, secret, frame)) {
                status = ResourceValueFrame.CLOSED;
                if (DEBUG) {
                    System.out.println("CLOSE");
                }
                if(resourceTracker.isNotDefinitelyClosedInTryCatchBlock(basicBlock, handle, cpg, secret, frame)) {
                    status = ResourceValueFrame.OPEN_ON_EXCEPTION_PATH;
                }
            }

            // Model use of instance values in frame slots
            analyzeInstruction(ins);

            final int updatedNumSlots = frame.getNumSlots();

            // Mark any appearances of the secret value in the ResourceValueFrame.
            ValueNumberFrame vnaFrame = vnaDataflow.getFactAfterLocation(new Location(handle, basicBlock));
            if (DEBUG) {
                System.out.println("vna frame after instruction: " + vnaFrame.toString());
                System.out.println("Secret value number: " + secret.getSecretValue());
                if (secret.getSecretValue().hasFlag(ValueNumber.RETURN_VALUE)) {
                    System.out.println("is return value");
                }
            }

            for (int i = 0; i < updatedNumSlots; ++i) {
                if (DEBUG) {
                    System.out.println("Slot " + i);
                    System.out.println("Secret value number: " + vnaFrame.getValue(i));
                    if (vnaFrame.getValue(i).hasFlag(ValueNumber.RETURN_VALUE)) {
                        System.out.println("  is return value");
                    }
                }
                if (vnaFrame.fuzzyMatch(secret.getSecretValue(), vnaFrame.getValue(i))) {
                    if (DEBUG) {
                        System.out.println("Saw lock value!");
                    }
                    frame.setValue(i, ResourceValue.instance());
                }
            }

            // If needed, update frame status
            if (status != -1) {
                frame.setStatus(status);
            }
            if (DEBUG) {
                System.out.println("resource frame after instruction: " + frame.toString());
            }

        }

        @Override
        protected boolean instanceEscapes(InvokeInstruction inv, int instanceArgNum) {
            return false;
        }
    }

    class SecretResourceTracker implements ResourceTracker<Secret> {
        private final RepositoryLookupFailureCallback lookupFailureCallback;

        private final CFG cfg;

        private final ValueNumberDataflow vnaDataflow;

        private final IsNullValueDataflow isNullDataflow;

        private final ClassContext classContext;

        private final Method method;

        private final MethodDescriptor methodDescriptor;


        public SecretResourceTracker(RepositoryLookupFailureCallback lookupFailureCallback, CFG cfg,
                                     ValueNumberDataflow vnaDataflow, IsNullValueDataflow isNullDataflow,
                                     ClassContext classContext, Method method) {
            this.lookupFailureCallback = lookupFailureCallback;
            this.cfg = cfg;
            this.vnaDataflow = vnaDataflow;
            this.isNullDataflow = isNullDataflow;
            this.classContext = classContext;
            this.method = method;
            this.methodDescriptor = new MethodDescriptor(ClassName.toSlashedClassName(classContext.getJavaClass().getSourceFileName()),
                    method.getName(),
                    method.getSignature(),
                    method.isStatic());
        }

        @Override
        public Secret isResourceCreation(BasicBlock basicBlock, InstructionHandle handle, ConstantPoolGen cpg)
                throws DataflowAnalysisException {

            InvokeInstruction inv = toInvokeInstruction(handle.getInstruction());
            if (inv == null) {
                return null;
            }

            String className = inv.getClassName(cpg);
            String methodName = inv.getName(cpg);
            String methodSig = inv.getSignature(cpg);

            if ("<init>".equals(methodName) && "(Ljava/lang/String;)V".equals(methodSig)
                    && className.contains("com.nimbusds.oauth2.sdk.auth.Secret")) {

                Location location = new Location(handle, basicBlock);
                ValueNumberFrame frame = vnaDataflow.getFactAtLocation(location);
                ValueNumber secretValue = frame.getTopValue();
                if (DEBUG) {
                    System.out.println("Secret value is " + secretValue.getNumber() + ", frame=" + frame.toString());
                }
                if (DEBUG) {
                    ++numAcquires;
                }
                return new Secret(location, className, secretValue);
            }

            return null;
        }

        public boolean isNotDefinitelyClosedInTryCatchBlock(BasicBlock basicBlock, InstructionHandle handle, ConstantPoolGen cpg, Secret secret,
                                                            ResourceValueFrame frame) throws DataflowAnalysisException {
            CodeExceptionGen exceptionGen;
            IAnalysisCache analysisCache = Global.getAnalysisCache();
            StandardTypeMerger merger = null;
            ExceptionSetFactory exceptionSetFactory;
            ExceptionHandlerMap exceptionHandlerMap;

            try {
                exceptionSetFactory = analysisCache.getMethodAnalysis(ExceptionSetFactory.class, methodDescriptor
                );
                merger = new StandardTypeMerger(AnalysisContext.currentAnalysisContext()
                        .getLookupFailureCallback(), exceptionSetFactory);
                exceptionHandlerMap  = new ExceptionHandlerMap(classContext.getMethodGen(method), merger);

                exceptionGen = exceptionHandlerMap.getHandlerForStartInstruction(secret.getLocation().getHandle());
                CodeException codeException = exceptionGen.getCodeException(cpg);
                if(exceptionGen.containsTarget(handle) && exceptionGen.containsTarget(secret.getLocation().getHandle())) {
                    if(codeException.getStartPC() <= secret.getLocation().getHandle().getPosition()) {
                        // Check
                        if(secret.getLocation().compareTo(new Location(handle, basicBlock)) > 2) {

                            // open 3
                            // 4 New Secret
                            // blablafoo(); An error can be thrown between create and release!
                            // 6 Secret.erase()


                            // 20
                            //b range 1 -- 9   target 20

                            // Secret.erase()
                            return true;
                        }
                    }

                }

            } catch (CheckedAnalysisException e) {
                AnalysisContext.logError("Unable to generate exceptionSetFactory for " + methodDescriptor, e);
            } catch (NullPointerException e) {
                AnalysisContext.logError("No methodgen in method " + method.getName() + " in class "+ classContext.getJavaClass().getClassName());
            }

            return false;
        }

        @Override
        public boolean mightCloseResource(BasicBlock basicBlock, InstructionHandle handle, ConstantPoolGen cpg)
                throws DataflowAnalysisException {
            InvokeInstruction inv = toInvokeInstruction(handle.getInstruction());
            if (inv == null) {
                return false;
            }

            String className = inv.getClassName(cpg);
            String methodName = inv.getName(cpg);
            String methodSig = inv.getSignature(cpg);

            return "erase".equals(methodName) && "()V".equals(methodSig)
                    && (className.contains("com.nimbusds.oauth2.sdk.auth.Secret")
                    || className.contains("Secret"));
        }

        @Override
        public boolean isResourceClose(BasicBlock basicBlock, InstructionHandle handle, ConstantPoolGen cpg, Secret resource,
                                       ResourceValueFrame frame) throws DataflowAnalysisException {
            return mightCloseResource(basicBlock, handle, cpg);
        }

        @Override
        public ResourceValueFrameModelingVisitor createVisitor(Secret resource, ConstantPoolGen cpg) {

            return new SecretFrameModelingVisitor(cpg, this, resource, vnaDataflow, isNullDataflow);
        }

        @Override
        public boolean ignoreImplicitExceptions(Secret secret) {

            return false;
        }

        @Override
        public boolean ignoreExceptionEdge(Edge edge, Secret resource, ConstantPoolGen cpg) {
            try {
           // TODO: handle this feature properly
                Location location = cfg.getExceptionThrowerLocation(edge);
                if (DEBUG) {
                    System.out.println("Exception thrower location: " + location);
                }
                Instruction ins = location.getHandle().getInstruction();

                if (ins instanceof GETFIELD) {
                    GETFIELD insGetfield = (GETFIELD) ins;
                    String fieldName = insGetfield.getFieldName(cpg);
                    if (DEBUG) {
                        System.out.println("Inspecting GETFIELD of " + fieldName + " at " + location);
                    }
                    // Ignore exceptions from getfield instructions where the
                    // object reference is known not to be null
                    if ("secret".equals(fieldName) || "token".equals(fieldName) || "password".equals(fieldName)) {
                        return true;
                    }
                    IsNullValueFrame frame = isNullDataflow.getFactAtLocation(location);
                    if (!frame.isValid()) {
                        return false;
                    }
                    IsNullValue receiver = frame.getInstance(ins, cpg);
                    boolean notNull = receiver.isDefinitelyNotNull();
                    if (DEBUG && notNull) {
                        System.out.println("Ignoring exception from non-null GETFIELD");
                    }
                    return notNull;
                } else if (ins instanceof InvokeInstruction) {
                    InvokeInstruction iins = (InvokeInstruction) ins;
                    String methodName = iins.getMethodName(cpg);

                    if ("getValue".equals(methodName) || "<init>".equals(methodName) || "erase".equals(methodName)) {
                        return true;
                    }
                }
                if (DEBUG) {
                    System.out.println("FOUND Exception thrower at: " + location);
                }
            } catch (DataflowAnalysisException e) {
                AnalysisContext.logError("Error while looking for exception edge", e);
            }

            return false;
        }

        @Override
        public boolean isParamInstance(Secret resource, int slot) {
            // There is nothing special about Lock objects passed
            // into the method as parameters.
            return false;
        }

        private InvokeInstruction toInvokeInstruction(Instruction ins) {
            short opcode = ins.getOpcode();
            if (opcode == Const.INVOKEVIRTUAL || opcode == Const.INVOKESPECIAL) {
                return (InvokeInstruction) ins;
            }
            return null;
        }
    }

    /*
     * ----------------------------------------------------------------------
     * Implementation
     * ----------------------------------------------------------------------
     */


    private static final String UNSAFE_DELETE_SECRET_AUTH = "UNSAFE_DELETE_SECRET_AUTH";
    private static final String UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH = "UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH";
    private BugReporter bugReporter;

    public InsecureDeleteSecretDetector(BugReporter bugReporter) {
        super(bugReporter);
    }



    /*
     * (non-Javadoc)
     *
     * @see
     * edu.umd.cs.findbugs.Detector#visitClassContext(edu.umd.cs.findbugs.ba
     * .ClassContext)
     */
    @Override
    public void visitClassContext(ClassContext classContext) {
        JavaClass javaClass = classContext.getJavaClass();

        // We can ignore classes that were compiled for anything
        // less than JDK 1.5. This should avoid lots of unnecessary work
        // when analyzing code for older VM targets.
        if (BCELUtil.preTiger(javaClass)) {
            return;
        }

        boolean sawAuth = false;
        for (Constant c : javaClass.getConstantPool().getConstantPool()) {
            if (c instanceof ConstantMethodref) {
                ConstantMethodref m = (ConstantMethodref) c;
                ConstantClass cl = (ConstantClass) javaClass.getConstantPool().getConstant(m.getClassIndex());
                ConstantUtf8 name = (ConstantUtf8) javaClass.getConstantPool().getConstant(cl.getNameIndex());
                String nameAsString = name.getBytes();
                if (nameAsString.startsWith("com/nimbusds/oauth2/sdk/auth")) {
                    sawAuth = true;
                    break;
                }
            }
        }
        if (sawAuth) {
            super.visitClassContext(classContext);
        }
    }



    @Override
    public boolean prescreen(ClassContext classContext, Method method, boolean mightClose) {
        if (!mightClose) {
            return false;
        }
        BitSet bytecodeSet = classContext.getBytecodeSet(method);
        if (bytecodeSet == null) {
            return false;
        }

        MethodGen methodGen = classContext.getMethodGen(method);

        return methodGen != null && !methodGen.getName().toLowerCase().contains("auth")
                && (bytecodeSet.get(Const.INVOKEVIRTUAL) || bytecodeSet.get(Const.INVOKESPECIAL));
    }

    public boolean prescreennew(ClassContext classContext, Method method, boolean mightClose) {
        IAnalysisCache analysisCache = Global.getAnalysisCache();
        MethodDescriptor methodDescriptor = new MethodDescriptor(classContext.getJavaClass().getClassName(),
                method.getName(),
                method.getSignature(),
                method.isStatic());
        StandardTypeMerger merger = null;
        ExceptionSetFactory exceptionSetFactory;
        MethodGen methodGen = null;
        ExceptionHandlerMap exceptionHandlerMap;
        if (!mightClose) {
            return false;
        }

        BitSet bytecodeSet = classContext.getBytecodeSet(method);
        if (bytecodeSet == null) {
            return false;
        }

        try {
            exceptionSetFactory = analysisCache.getMethodAnalysis(ExceptionSetFactory.class, methodDescriptor
            );
            merger = new StandardTypeMerger(AnalysisContext.currentAnalysisContext()
                    .getLookupFailureCallback(), exceptionSetFactory);
            exceptionHandlerMap  = new ExceptionHandlerMap(classContext.getMethodGen(method), merger);
        } catch (CheckedAnalysisException e) {
            AnalysisContext.logError("Unable to generate exceptionSetFactory for " + methodDescriptor, e);
        } catch (NullPointerException e) {
            AnalysisContext.logError("No methodgen in method " + method.getName() + " in class "+ classContext.getJavaClass().getClassName());
        }



        return  !methodGen.getName().toLowerCase().contains("auth")
                && (bytecodeSet.get(Const.INVOKEVIRTUAL) || bytecodeSet.get(Const.INVOKESPECIAL));


    }


    @Override
    public SecretResourceTracker getResourceTracker(ClassContext classContext, Method method) throws CFGBuilderException,
            DataflowAnalysisException {
        return new SecretResourceTracker(bugReporter, classContext.getCFG(method), classContext.getValueNumberDataflow(method),
                classContext.getIsNullValueDataflow(method), classContext, method);
    }

    @Override
    public void inspectResult(ClassContext classContext, MethodGen methodGen, CFG cfg,
                              Dataflow<ResourceValueFrame, ResourceValueAnalysis<Secret>> dataflow, Secret resource) {

        JavaClass javaClass = classContext.getJavaClass();

        ResourceValueFrame exitFrame = dataflow.getResultFact(cfg.getExit());
        if (DEBUG) {
            System.out.println("Resource value at exit: " + exitFrame);
        }
        int exitStatus = exitFrame.getStatus();

        if (exitStatus == ResourceValueFrame.OPEN || exitStatus == ResourceValueFrame.OPEN_ON_EXCEPTION_PATH) {
            String bugType;
            int priority;
            if (exitStatus == ResourceValueFrame.OPEN) {
            bugType = UNSAFE_DELETE_SECRET_AUTH;
            priority = NORMAL_PRIORITY;
            } else {
                 bugType = UNSAFE_DELETE_SECRET_AUTH_EXCEPTION_PATH;
                 priority = NORMAL_PRIORITY;
             }
            String sourceFile = javaClass.getSourceFileName();
            Location location = resource.getLocation();
            InstructionHandle handle = location.getHandle();
            InstructionHandle nextInstruction = handle.getNext();
            if (nextInstruction.getInstruction() instanceof RETURN) {
                return; // don't report as error; intentional
            }
            bugAccumulator.accumulateBug(new BugInstance(this, bugType, priority).addClassAndMethod(methodGen, sourceFile),
                    SourceLineAnnotation.fromVisitedInstruction(classContext, methodGen, sourceFile, handle));
        }
    }

    @Override
    public void report() {
        if (DEBUG) {
            System.out.println("numAcquires=" + numAcquires);
        }
    }

    // /* ----------------------------------------------------------------------
    // * Test main() driver
    // * ----------------------------------------------------------------------
    // */
    //
    // public static void main(String[] argv) throws Exception {
    // if (argv.length != 3) {
    // System.err.println("Usage: " + FindUnreleasedLock.class.getName() +
    // " <class file> <method name> <bytecode offset>");
    // System.exit(1);
    // }
    //
    // String classFile = argv[0];
    // String methodName = argv[1];
    // int offset = Integer.parseInt(argv[2]);
    // final FindUnreleasedLock detector = new FindUnreleasedLock(null);
    //
    // ResourceValueAnalysisTestDriver<Lock, LockResourceTracker> driver =
    // new ResourceValueAnalysisTestDriver<Lock, LockResourceTracker>() {
    // @Override
    // public LockResourceTracker createResourceTracker(ClassContext
    // classContext, Method method)
    // throws CFGBuilderException, DataflowAnalysisException {
    //
    // RepositoryLookupFailureCallback lookupFailureCallback =
    // classContext.getLookupFailureCallback();
    //
    // return detector.new LockResourceTracker(
    // lookupFailureCallback,
    // classContext.getCFG(method),
    // classContext.getValueNumberDataflow(method),
    // classContext.getIsNullValueDataflow(method));
    // }
    // };
    //
    // driver.execute(classFile, methodName, offset);
    // }
}
