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
import com.h3xstream.findsecbugs.oidc.data.cfg.NonceVerifyBlockTrail;
import com.h3xstream.findsecbugs.oidc.data.cfg.ReturnBlockTrail;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.*;
import org.apache.bcel.Const;
import org.apache.bcel.classfile.JavaClass;
import org.apache.bcel.classfile.Method;
import org.apache.bcel.generic.*;

import java.io.PrintStream;
import java.util.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static com.h3xstream.findsecbugs.common.matcher.InstructionDSL.invokeInstruction;

public class TokenValidationCFGAnalysis implements Detector {
    CFGPrinter printer;
    private final BugReporter bugReporter;
    public TokenValidationCFGAnalysis(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    private final static String IMPROPER_TOKEN_VERIFY_CONTROL_FLOW = "IMPROPER_TOKEN_VERIFY_CONTROL_FLOW";
    private final static String REVERSED_IF_EQUALS_ID_TOKEN_VERIFY = "REVERSED_IF_EQUALS_ID_TOKEN_VERIFY";

    private final String GOOGLE_ID_TOKEN_RESPONSE= "com/google/api/client/auth/openidconnect/IdTokenResponse";
    private final String GOOGLE_ID_TOKEN = "Lcom/google/api/client/auth/openidconnect/IdToken";


    private final InvokeMatcherBuilder
            GOOGLE_PARSE_TOKEN_INVOKE = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdTokenResponse")
            .atMethod("parseIdToken")
            .withArgs("()Lcom/google/api/client/auth/openidconnect/IdToken;");
    // Verify nonce:
    private final InvokeMatcherBuilder
            GOOGLE_ID_TOKEN_GET_NONCE = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdToken$Payload")
            .atMethod("getNonce");
    private final InvokeMatcherBuilder
            STRING_EQUALS = invokeInstruction()
                .atClass("java/lang/String")
                .atMethod("equals")
                .withArgs("(Ljava/lang/Object;)Z");
    private final InvokeMatcherBuilder
            GOOGLE_ID_TOKEN_VER_SIGN = invokeInstruction()
                .atClass("com/google/api/client/auth/openidconnect/IdToken")
                .atMethod("verifySignature");
    private final InvokeMatcherBuilder
            GOOGLE_ID_TOKEN_VER_AUD = invokeInstruction()
                .atClass("com/google/api/client/auth/openidconnect/IdToken")
                .atMethod("verifyAudience");

    private final InvokeMatcherBuilder
            GOOGLE_ID_TOKEN_VER_EXP = invokeInstruction()
                .atClass("com/google/api/client/auth/openidconnect/IdToken")
                .atMethod("verifyExpirationTime","verifyTime","verifyIssuedAtTime");

    private final InvokeMatcherBuilder
            GOOGLE_ID_TOKEN_VER_ISS = invokeInstruction()
                .atClass("com/google/api/client/auth/openidconnect/IdToken")
                .atMethod("verifyIssuer");


    private final List<InvokeMatcherBuilder>
            VERIFICATION_INVOCATIONS = Arrays.asList(
                                            GOOGLE_ID_TOKEN_VER_SIGN,
                                            GOOGLE_ID_TOKEN_VER_AUD,
                                            GOOGLE_ID_TOKEN_VER_EXP,
                                            GOOGLE_ID_TOKEN_VER_ISS
                                        );

    private final InvokeMatcherBuilder
            RESPONSE_STATUS = invokeInstruction()
                .atClass("javax/ws/rs/core/Response")
                .atMethod("status");


    private static final BitSet ifInstructionSet = new BitSet();

    static {
        ifInstructionSet.set(Const.IF_ACMPEQ);
        ifInstructionSet.set(Const.IF_ACMPNE);
        ifInstructionSet.set(Const.IF_ICMPEQ);
        ifInstructionSet.set(Const.IF_ICMPNE);
        ifInstructionSet.set(Const.IF_ICMPLT);
        ifInstructionSet.set(Const.IF_ICMPLE);
        ifInstructionSet.set(Const.IF_ICMPGT);
        ifInstructionSet.set(Const.IF_ICMPGE);
        ifInstructionSet.set(Const.IFEQ);
        ifInstructionSet.set(Const.IFNE);
        ifInstructionSet.set(Const.IFLT);
        ifInstructionSet.set(Const.IFLE);
        ifInstructionSet.set(Const.IFGT);
        ifInstructionSet.set(Const.IFGE);
        ifInstructionSet.set(Const.IFNULL);
        ifInstructionSet.set(Const.IFNONNULL);
    }

    private boolean idTokenInSignature(MethodGen methodGen) {
        return methodGen.getSignature().contains(GOOGLE_ID_TOKEN)
        || methodGen.getSignature().contains(GOOGLE_ID_TOKEN_RESPONSE);
    }

    private boolean instructionListIndicatesIdTokenValidation(InstructionList instructionList, ConstantPoolGen cpg) {
        for (InstructionHandle instructionHandle : instructionList) {
            Instruction instruction = instructionHandle.getInstruction();
            if(instructionMatchesIdTokenValidate(instruction, cpg)) {
                return true;
            }
        }
        return false;
    }

    private boolean instructionMatchesIdTokenValidate(Instruction instruction, ConstantPoolGen cpg) {
        if(instruction instanceof InvokeInstruction) {
            return VERIFICATION_INVOCATIONS.stream().anyMatch(i -> i.matches(instruction, cpg));
        }
        return false;
    }

    private BasicBlock searchReturnBlockAfterConditional(BasicBlock basicBlock, CFG cfg, ConstantPoolGen cpg, int depthSafetyCounter, ReturnBlockTrail returnBlockTrail) {
        if(basicBlock == null || cfg == null) return null;

        Edge ft = cfg.getOutgoingEdgeWithType(basicBlock, EdgeTypes.FALL_THROUGH_EDGE);
        if(ft == null) return null;
        BasicBlock targetBlock = ft.getTarget();
        if(targetBlock == null) return null;
        Iterable<InstructionHandle> iterableIns = () -> targetBlock.instructionIterator();

        if(isTokenVerifyBlock(targetBlock, cfg, cpg)) {
            // We reached new verify block and have fallen through without return. OOPS!
            return null;
        }

        boolean foundHttpResponseStatus = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> {
                    if(RESPONSE_STATUS.matches(i.getInstruction(), cpg)) {
                        return true;
                    } else if(i.getInstruction() instanceof InvokeInstruction) {
                        InvokeInstruction newThrow = (InvokeInstruction) i.getInstruction();
                        return newThrow.getName(cpg).contains("Exception");
                    } else if(i.getInstruction() instanceof ATHROW) {
                        return true;
                    }
                    return false;
                } );

        boolean foundHttp400sCode = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> {
                    if(i.getInstruction() instanceof GETSTATIC) {
                        FieldInstruction getstatic = (GETSTATIC) i.getInstruction();
                        return getstatic.getFieldName(cpg).equals("UNAUTHORIZED");
                    } else if(i.getInstruction() instanceof InvokeInstruction) {
                        InvokeInstruction newThrow = (InvokeInstruction) i.getInstruction();
                        return newThrow.getName(cpg).contains("Exception");
                    } else if(i.getInstruction() instanceof ATHROW) {
                        return true;
                    }
                    return false;
                });


        returnBlockTrail.addBlockToTrail(targetBlock);

        if(foundHttpResponseStatus) {
            returnBlockTrail.setFoundHttpResponseStatus(true);
        }
        if(foundHttp400sCode) {
            returnBlockTrail.setFoundResponseIndicatingInvalidation(true);
        }
        if(isReturnBlock(targetBlock, cfg)) {
            returnBlockTrail.setFoundReturnStatement(true);
            return targetBlock;
        }

        if(depthSafetyCounter > 25) return null;
        return searchReturnBlockAfterConditional(targetBlock, cfg, cpg, depthSafetyCounter+1, returnBlockTrail);
    }


    private boolean foundReturnBlockAfterIf(BasicBlock basicBlock, CFG cfg, ConstantPoolGen cpg) {
        ReturnBlockTrail returnBlockTrail = new ReturnBlockTrail(basicBlock);
        BasicBlock returnBlock = searchReturnBlockAfterConditional(basicBlock, cfg, cpg, 1, returnBlockTrail);
        if(returnBlock == null) return false;
        return returnBlockTrail.foundReturnStatement() && returnBlockTrail.foundResponseIndicationInvalidation() && returnBlockTrail.foundHttpResponseStatus();//
    }

     private boolean isReturnBlock(BasicBlock basicBlock, CFG cfg) {

            Edge ret = cfg.getOutgoingEdgeWithType(basicBlock, EdgeTypes.RETURN_EDGE);
            Edge athrow = cfg.getOutgoingEdgeWithType(basicBlock, EdgeTypes.HANDLED_EXCEPTION_EDGE);
            Iterable<InstructionHandle> iterableIns = () -> basicBlock.instructionIterator();

            boolean foundReturnStatement = StreamSupport.stream(iterableIns.spliterator(), false)
                    .anyMatch(i -> i.getInstruction().getOpcode() == Const.ARETURN);
            boolean foundThrowStatement = StreamSupport.stream(iterableIns.spliterator(), false)
                    .anyMatch(i -> i.getInstruction().getOpcode() == Const.ATHROW);
            return (ret != null && foundReturnStatement) || (athrow != null && foundThrowStatement);
        }


    private BasicBlock findBlockWithGetNonce(BasicBlock b, CFG cfg, ConstantPoolGen cpg, NonceVerifyBlockTrail trail) {
        // Nonce verify for google is especially hard since it's stringly typed.
        Iterable<InstructionHandle> iterableIns = () -> b.instructionIterator();
        boolean hasTokenParse = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> GOOGLE_PARSE_TOKEN_INVOKE.matches(i.getInstruction(), cpg));
        trail.addBlockToTrail(b);
        if(hasTokenParse) {
            // Exit condition: we can be certain that nonce is not check before token response is parsed
            return b;
        }
        boolean hasStringEquals = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> STRING_EQUALS.matches(i.getInstruction(), cpg));
        boolean hasGetNonce = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> GOOGLE_ID_TOKEN_GET_NONCE.matches(i.getInstruction(), cpg));

        if(hasStringEquals) {
            trail.setFoundStringEquals(true);
        }
        if(hasGetNonce) {
            trail.setFoundGetNonce(true);
            return b;
        }
        // Check preceding blocks for nonce
        Edge incomingFallThrough = cfg.getIncomingEdgeWithType(b, EdgeTypes.FALL_THROUGH_EDGE);
        if(incomingFallThrough != null) {
            BasicBlock prev = incomingFallThrough.getSource();
            return findBlockWithGetNonce(prev, cfg, cpg, trail);
        }
        return null;
    }

    private boolean hasNonceVerify(BasicBlock b, CFG cfg, ConstantPoolGen cpg) {
        NonceVerifyBlockTrail trail = new NonceVerifyBlockTrail(b);
        BasicBlock foundBlockWithGetNonce = findBlockWithGetNonce(b, cfg, cpg, trail);
        if(foundBlockWithGetNonce == null) return false;
        return trail.foundStringEquals() && trail.foundGetNonce();
    }

    private boolean isTokenVerifyBlock(BasicBlock b, CFG cfg, ConstantPoolGen cpg) {
        /*FIXME: this has the assumption that a call to verify won't be in a previous block
           therefore prone to FPs per now. Have to trace values. Probably another argument for dfa */
        Iterable<InstructionHandle> iterableIns = () -> b.instructionIterator();
        boolean isIfBlock = isIfConditionalBlock(b, cfg);
        boolean hasNonceVerify = false;
        boolean hasValidateIDTokenFunction = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> instructionMatchesIdTokenValidate(i.getInstruction(), cpg));
        if(isIfBlock && !hasValidateIDTokenFunction) {
            hasNonceVerify = hasNonceVerify(b, cfg, cpg);
        }
       return isIfBlock
                && (hasValidateIDTokenFunction || hasNonceVerify);
    }

    private boolean isIfConditionalBlock(BasicBlock b, CFG cfg) {
        /*FIXME: this has the assumption that a call to verify won't be in a previous block
           therefore prone to FPs per now. Have to trace values. Probably another argument for dfa */
        Iterable<InstructionHandle> iterableIns = () -> b.instructionIterator();
        Edge ifEdge = cfg.getOutgoingEdgeWithType(b, EdgeTypes.IFCMP_EDGE);
        Edge fallthroughEdge = cfg.getOutgoingEdgeWithType(b, EdgeTypes.FALL_THROUGH_EDGE);
        boolean hasOutgoingIfEdges = (ifEdge != null && fallthroughEdge != null);
        boolean hasAnyIfInstruction =  StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> ifInstructionSet.get(i.getInstruction().getOpcode()));
        return  hasOutgoingIfEdges
                && hasAnyIfInstruction;
    }

    private boolean missingIfNeConditional(BasicBlock b) {
        Iterable<InstructionHandle> iterableIns = () -> b.instructionIterator();
        boolean hasIfNeInstruction =  StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> Const.IFNE == i.getInstruction().getOpcode());
        return !hasIfNeInstruction;
    }

    private Optional<InvokeInstruction> getVerifyInvokeFromBasicBlock(BasicBlock b, ConstantPoolGen cpg) {
        Iterable<InstructionHandle> iterableIns = () -> b.instructionIterator();
        return StreamSupport.stream(iterableIns.spliterator(), false)
                .filter(i -> instructionMatchesIdTokenValidate(i.getInstruction(), cpg)
                            || STRING_EQUALS.matches(i.getInstruction(), cpg)) // FIXME: Nonce is troublesome. Add similar search to find more relevant ins
                .map(i -> (InvokeInstruction)i.getInstruction())
                .findFirst();
    }

    @Override
    public void visitClassContext(ClassContext classContext) {
        //printCFGDetailsAnalysis(classContext);
        //printCFG(classContext);
        JavaClass javaClass = classContext.getJavaClass();

        for (Method m : javaClass.getMethods()) {
            MethodGen methodGen = classContext.getMethodGen(m);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }
            if(idTokenInSignature(methodGen) || instructionListIndicatesIdTokenValidation(methodGen.getInstructionList(), cpg)) {
                try {
                    CFG cfg = classContext.getCFG(m);
                    Iterator<BasicBlock> basicBlockIterator = cfg.blockIterator();
                    while (basicBlockIterator.hasNext()) {
                        BasicBlock b = basicBlockIterator.next();
                        if(isTokenVerifyBlock(b, cfg, cpg)) {
                            if(missingIfNeConditional(b)) {
                                BugInstance bugInstance = new BugInstance(this, REVERSED_IF_EQUALS_ID_TOKEN_VERIFY, Priorities.NORMAL_PRIORITY)
                                        .addClassAndMethod(javaClass, m);
                                Optional<InvokeInstruction> verifyIns = getVerifyInvokeFromBasicBlock(b, cpg);
                                verifyIns.ifPresent(invokeInstruction -> bugInstance.addCalledMethod(cpg, invokeInstruction));
                                bugReporter.reportBug(bugInstance);
                            }
                            if(!foundReturnBlockAfterIf(b, cfg, cpg)) {
                                BugInstance bugInstance = new BugInstance(this, IMPROPER_TOKEN_VERIFY_CONTROL_FLOW, Priorities.HIGH_PRIORITY)
                                        .addClassAndMethod(javaClass, m);
                                Optional<InvokeInstruction> verifyIns = getVerifyInvokeFromBasicBlock(b, cpg);
                                verifyIns.ifPresent(invokeInstruction -> bugInstance.addCalledMethod(cpg, invokeInstruction));
                                bugReporter.reportBug(bugInstance);
                            }
                        }
                    }
                } catch (CFGBuilderException e) {
                    //
                }
            }
        }
    }


    private void printCFG(ClassContext classContext) {
        for (Method m : classContext.getJavaClass().getMethods())
            if(m.getName().contains("OK_validateTokensThrow") || m.getName().equals("simpleCFGAnalyzed1") || m.getName().equals("simpleCFGAnalyzed2")) {
                try {
                    CFG cfg =  classContext.getCFG(m);
                    printer = new CFGPrinter(cfg);
                    PrintStream printStream = new PrintStream(System.out);
                    printer.print(printStream);
                } catch(CFGBuilderException e) {
                    //
                }
            }
    }

    private void printCFGDetailsAnalysis(ClassContext classContext) {
        JavaClass javaClass = classContext.getJavaClass();
        printCFG(classContext);
        for (Method m : classContext.getJavaClass().getMethods()) {
            if(m.getName().equals("validateTokens")) {
                try {
                    CFG cfg = classContext.getCFG(m);
                    ConstantPoolGen cpg = classContext.getConstantPoolGen();
                    Iterator<BasicBlock> basicBlockIterator = cfg.blockIterator();
                    List<Instruction> instructions = new ArrayList<>();
                    basicBlockIterator
                            .forEachRemaining(
                                    b -> b.instructionIterator()
                                            .forEachRemaining(i -> instructions.add(i.getInstruction()))
                            );
                    System.out.println("Instructions: ");
                    instructions.forEach(i -> {
                        System.out.println(i);
                        if((i instanceof InvokeInstruction)) {
                            InvokeInstruction invokeInstruction = (InvokeInstruction) i;
                            System.out.println(invokeInstruction.getMethodName(cpg));
                            System.out.println(invokeInstruction.getSignature(cpg));
                        }
                    });
                    basicBlockIterator.forEachRemaining(b -> {
                                Edge ft = cfg.getOutgoingEdgeWithType(b, EdgeTypes.FALL_THROUGH_EDGE);
                                Edge ifed = cfg.getOutgoingEdgeWithType(b, EdgeTypes.IFCMP_EDGE);
                                Iterable<InstructionHandle> iterableIns = () -> b.instructionIterator();
                                Stream<InstructionHandle> insStream = StreamSupport.stream(iterableIns.spliterator(), false);
                                if(ifed != null  || ft != null) { // We are in an if block?
                                    insStream.forEachOrdered(i -> {
                                        Instruction instruction = i.getInstruction();
                                        if(!(instruction instanceof InvokeInstruction)) {
                                            return;
                                        }
                                        InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;
                                        if(invokeInstruction instanceof INVOKESPECIAL
                                                && invokeInstruction.getReturnType(cpg) == Type.BOOLEAN) {

                                        }
                                        System.out.println(invokeInstruction.getMethodName(cpg));
                                    });
                                }

                            }
                    );
                } catch (CFGBuilderException e) {
                    //
                }
            }
        }
    }

    @Override
    public void report() {

    }


}
