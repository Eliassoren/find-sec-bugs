package com.h3xstream.findsecbugs.oidc.authorizationcodeflow.token;

import com.h3xstream.findsecbugs.common.matcher.InvokeMatcherBuilder;
import com.h3xstream.findsecbugs.oidc.data.ReturnBlockTrail;
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

    private final String IMPROPER_TOKEN_VERIFY_CONTROL_FLOW = "IMPROPER_TOKEN_VERIFY_CONTROL_FLOW";

    private final String GOOGLE_ID_TOKEN_RESPONSE= "com/google/api/client/auth/openidconnect/IdTokenResponse";
    private final String GOOGLE_ID_TOKEN = "Lcom/google/api/client/auth/openidconnect/IdToken";


    private final InvokeMatcherBuilder
            GOOGLE_PARSE_TOKEN_INVOKE = invokeInstruction()
            .atClass("com/google/api/client/auth/openidconnect/IdTokenResponse")
            .atMethod("parseIdToken");
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
                .atMethod("verifyExpirationTime");
    private final InvokeMatcherBuilder
            GOOGLE_ID_TOKEN_VER_ISS = invokeInstruction()
                .atClass("com/google/api/client/auth/openidconnect/IdToken")
                .atMethod("verifyIssuer");


    private final List<InvokeMatcherBuilder>
            VERIFICATION_INVOCATIONS = Arrays.asList(
                                            GOOGLE_ID_TOKEN_GET_NONCE,
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

    private boolean instructionListIndicatesIdToken(InstructionList instructionList, ConstantPoolGen cpg) {
        for (InstructionHandle instructionHandle : instructionList) {
            Instruction instruction = instructionHandle.getInstruction();
            if (!(instruction instanceof InvokeInstruction)) {
                continue;
            }
            InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;
            if(GOOGLE_PARSE_TOKEN_INVOKE.matches(invokeInstruction, cpg)) {
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

    private BasicBlock searchReturnBlockAfterBlock(BasicBlock basicBlock, CFG cfg, ConstantPoolGen cpg, int depthSafetyCounter, ReturnBlockTrail returnBlockTrail) {

        Edge ft = cfg.getOutgoingEdgeWithType(basicBlock, EdgeTypes.FALL_THROUGH_EDGE);
        BasicBlock targetBlock = ft.getTarget();

        Iterable<InstructionHandle> iterableIns = () -> targetBlock.instructionIterator();

        if(isTokenVerifyBlock(targetBlock, cfg, cpg)) {
            // We reached new verify block and have fallen through without return. OOPS!
            return null;
        }

        boolean foundHttpResponseStatus = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> RESPONSE_STATUS.matches(i.getInstruction(), cpg));

        boolean foundHttp400sCode = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> {
                    if(i.getInstruction() instanceof GETSTATIC) {
                        FieldInstruction getstatic = (GETSTATIC) i.getInstruction();
                        return getstatic.getFieldName(cpg).equals("UNAUTHORIZED");
                    }
                    return false;
                });


        returnBlockTrail.addBlockToTrail(targetBlock);

        if(foundHttpResponseStatus) {
            returnBlockTrail.setFoundHttpResponseStatus(true);
        }
        if(foundHttp400sCode) {
            returnBlockTrail.setFoundHttp400sCode(true);
        }
        if(isReturnBlock(targetBlock, cfg)) {
            returnBlockTrail.setFoundReturnStatement(true);
            return targetBlock;
        }
        if(depthSafetyCounter > 25) return null;
        return searchReturnBlockAfterBlock(targetBlock, cfg, cpg, depthSafetyCounter+1, returnBlockTrail);
    }


    private boolean foundReturnBlockAfterIf(BasicBlock basicBlock, CFG cfg, ConstantPoolGen cpg) {
        ReturnBlockTrail returnBlockTrail = new ReturnBlockTrail(basicBlock);
        BasicBlock returnBlock = searchReturnBlockAfterBlock(basicBlock, cfg, cpg, 1, returnBlockTrail);
        if(returnBlock == null) return false;
        return returnBlockTrail.foundReturnStatement() && returnBlockTrail.foundHttp400sCode() && returnBlockTrail.foundHttpResponseStatus();//
    }

     private boolean isReturnBlock(BasicBlock basicBlock, CFG cfg) {

            Edge ret = cfg.getOutgoingEdgeWithType(basicBlock, EdgeTypes.RETURN_EDGE);

            Iterable<InstructionHandle> iterableIns = () -> basicBlock.instructionIterator();

            boolean foundReturnStatement = StreamSupport.stream(iterableIns.spliterator(), false)
                    .anyMatch(i -> i.getInstruction().getOpcode() == Const.ARETURN);

            return ret != null && foundReturnStatement;
        }

    private boolean isTokenVerifyBlock(BasicBlock b, CFG cfg, ConstantPoolGen cpg) {
        Iterable<InstructionHandle> iterableIns = () -> b.instructionIterator();
        Edge ifed = cfg.getOutgoingEdgeWithType(b, EdgeTypes.IFCMP_EDGE);
        Edge fted = cfg.getOutgoingEdgeWithType(b, EdgeTypes.FALL_THROUGH_EDGE);
        // Edge ret = cfg.getOutgoingEdgeWithType(b, EdgeTypes.RETURN_EDGE);
        boolean hasOutgoingIfEdges = (ifed != null && fted != null);
        boolean hasIfInstruction =  StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> ifInstructionSet.get(i.getInstruction().getOpcode()));
        boolean hasValidateIDTokenFunction = StreamSupport.stream(iterableIns.spliterator(), false)
                .anyMatch(i -> instructionMatchesIdTokenValidate(i.getInstruction(), cpg));
       return  hasOutgoingIfEdges
               && hasIfInstruction
               && hasValidateIDTokenFunction;
    }

    private void printCFG(ClassContext classContext) {
        for (Method m : classContext.getJavaClass().getMethods())
            if(m.getName().equals("validateTokens") || m.getName().equals("simpleCFGAnalyzed1") || m.getName().equals("simpleCFGAnalyzed2")) {
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
    public void visitClassContext(ClassContext classContext) {
        //printCFGDetailsAnalysis(classContext);
        JavaClass javaClass = classContext.getJavaClass();
        for (Method m : javaClass.getMethods()) {
            MethodGen methodGen = classContext.getMethodGen(m);
            ConstantPoolGen cpg = classContext.getConstantPoolGen();
            if (methodGen == null || methodGen.getInstructionList() == null) {
                continue; //No instruction .. nothing to do
            }
            if(idTokenInSignature(methodGen) || instructionListIndicatesIdToken(methodGen.getInstructionList(), cpg)) {
                try {
                    CFG cfg = classContext.getCFG(m);

                    Iterator<BasicBlock> basicBlockIterator = cfg.blockIterator();
                    while (basicBlockIterator.hasNext()) {
                        BasicBlock b = basicBlockIterator.next();
                        Iterable<InstructionHandle> iterableIns = () -> b.instructionIterator();
                        if(isTokenVerifyBlock(b, cfg, cpg)) {

                                StreamSupport.stream(iterableIns.spliterator(), false).forEachOrdered(i -> {
                                    Instruction instruction = i.getInstruction();
                                    if (!(instruction instanceof InvokeInstruction)) {
                                        return;
                                    }
                                    InvokeInstruction invokeInstruction = (InvokeInstruction) instruction;
                                    if(GOOGLE_ID_TOKEN_VER_SIGN.matches(instruction, cpg)) {
                                        printCFG(classContext);
                                        System.out.println("Verify block:"+ b);
                                        if(!foundReturnBlockAfterIf(b, cfg, cpg)) {
                                            bugReporter.reportBug(
                                                    new BugInstance(this, IMPROPER_TOKEN_VERIFY_CONTROL_FLOW, Priorities.HIGH_PRIORITY)
                                                    .addClassAndMethod(javaClass, m));
                                        }
                                    }

                                });

                        }
                    }
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
