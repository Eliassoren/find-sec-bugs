package com.h3xstream.findsecbugs.oidc.data.cfg;

import edu.umd.cs.findbugs.ba.BasicBlock;

import java.util.ArrayList;
import java.util.List;

public class NonceVerifyBlockTrail {
    private final BasicBlock lastChildWithIfConditional;
    private List<BasicBlock> trail;
    private boolean foundStringEquals;
    private boolean foundGetNonce;
    public NonceVerifyBlockTrail(BasicBlock lastChildWithIfConditional) {
        this.lastChildWithIfConditional = lastChildWithIfConditional;
        trail = new ArrayList<>();
        trail.add(lastChildWithIfConditional);
        foundStringEquals = false;
        foundGetNonce = false;
    }

    public BasicBlock getLastChildWithIfConditional() {
        return lastChildWithIfConditional;
    }

    public List<BasicBlock> getTrail() {
        return trail;
    }

    public void addBlockToTrail(BasicBlock b) {
        trail.add(b);
    }

    public void setTrail(List<BasicBlock> trail) {
        this.trail = trail;
    }

    public boolean foundStringEquals() {
        return foundStringEquals;
    }

    public void setFoundStringEquals(boolean foundStringEquals) {
        this.foundStringEquals = foundStringEquals;
    }

    public boolean foundGetNonce() {
        return foundGetNonce;
    }

    public void setFoundGetNonce(boolean foundGetNonce) {
        this.foundGetNonce = foundGetNonce;
    }
}
