#!/usr/bin/env python3
# CONT.110 cont72: first-divergence comparator for the invoker hunt.
# Aligns the JIT exec_nostats trace (TRACEWINJ BEFORE lines) against the interp
# trace (INTERP_PCLOG lines) by PC sequence and reports the FIRST step where they
# diverge -- either a different PC at the same step (control-flow fork) or the SAME
# PC with a different a0/a1/a2 (computed-value fork). That first divergence + the
# wrong value = the invoker root (@auditor's step 4).
#
# Usage: trace-diff.py <jit_emu.log> <interp_emu.log>
#   jit    = /workspace/tmp/tracewin/emu.log       (TRACEWINJ BEFORE ...)
#   interp = /workspace/tmp/interp-trace-false/emu.log (INTERP_PCLOG ...)
import sys, re

def parse_jit(path):
    seq = []
    for l in open(path, errors='replace'):
        if 'TRACEWINJ BEFORE' not in l:
            continue
        d = dict(re.findall(r'(\bpc|op|a0|a1|a2|a3)=([0-9a-fA-Fx]+)', l))
        # pc field is 'pc=' but regs.pc= also present; take the first pc= (guest pc)
        m = re.search(r'\bpc=([0-9a-f]+)', l)
        if not m: continue
        seq.append({'pc': m.group(1),
                    'a0': d.get('a0',''), 'a1': d.get('a1',''),
                    'a2': d.get('a2',''), 'a3': d.get('a3','')})
    return seq

def parse_interp(path):
    seq = []
    for l in open(path, errors='replace'):
        if 'INTERP_PCLOG' not in l:
            continue
        m = re.search(r'pc=([0-9a-f]+).*a0=([0-9a-f]+).*a1=([0-9a-f]+).*a2=([0-9a-f]+)', l)
        if not m: continue
        seq.append({'pc': m.group(1), 'a0': m.group(2),
                    'a1': m.group(3), 'a2': m.group(4), 'a3': ''})
    return seq

def main():
    if len(sys.argv) < 3:
        print("usage: trace-diff.py <jit_emu.log> <interp_emu.log>"); return 2
    jit = parse_jit(sys.argv[1]); interp = parse_interp(sys.argv[2])
    print(f"JIT steps: {len(jit)}   interp steps: {len(interp)}")
    n = min(len(jit), len(interp))
    for i in range(n):
        j, p = jit[i], interp[i]
        if j['pc'] != p['pc']:
            print(f"\n*** FIRST DIVERGENCE @ step {i}: CONTROL-FLOW fork ***")
            print(f"  JIT    pc={j['pc']} a0={j['a0']} a1={j['a1']} a2={j['a2']} a3={j['a3']}")
            print(f"  interp pc={p['pc']} a0={p['a0']} a1={p['a1']} a2={p['a2']}")
            print(f"  prev common pc={jit[i-1]['pc'] if i else '(start)'}")
            return 0
        for r in ('a0','a1','a2'):
            if j[r] and p[r] and j[r] != p[r]:
                print(f"\n*** FIRST DIVERGENCE @ step {i}: COMPUTED-VALUE fork (same pc={j['pc']}, {r} differs) ***")
                print(f"  JIT    {r}={j[r]}  (a0={j['a0']} a1={j['a1']} a2={j['a2']} a3={j['a3']})")
                print(f"  interp {r}={p[r]}  (a0={p['a0']} a1={p['a1']} a2={p['a2']})")
                return 0
    print(f"\nno divergence in first {n} common steps (widen window / raise B2_TRACE_LIMIT)")
    return 0

sys.exit(main())
