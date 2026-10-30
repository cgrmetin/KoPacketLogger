import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import java.io.*;

public class DumpDecomp extends GhidraScript {
    private static final long[] ADDRS = {
        0x14070F4C0L, 0x140AE7130L,
        0x14084A970L,
        0x140841D70L,
        0x14081B5E0L,
        0x140838A60L,
        0x140E68C50L,
        0x1407FA640L,
        0x140834A50L,
        0x1407E3070L,
        0x1409AE6E0L,
        0x14070B160L
    };

    public void run() throws Exception {
        PrintWriter w = new PrintWriter(new FileWriter(new File("D:/CheatKo/KoPacketLogger/.tmp_decomp.txt")));
        w.println("imageBase=" + currentProgram.getImageBase());
        w.println("minAddr=" + currentProgram.getMinAddress() + " maxAddr=" + currentProgram.getMaxAddress());
        w.println("funcCount=" + currentProgram.getFunctionManager().getFunctionCount());
        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.toggleSyntaxTree(true);
        di.openProgram(currentProgram);
        for (long la : ADDRS) {
            Address a = toAddr(la);
            Function f = getFunctionAt(a);
            w.println("=== 0x" + Long.toHexString(la) + " mapped=" + (a != null) + " fn=" + (f == null ? "NULL" : f.getName()));
            if (f == null && a != null) {
                Function c = getFunctionContaining(a);
                w.println("containing=" + (c == null ? "NULL" : c.getName() + "@" + c.getEntryPoint()));
                Instruction ins = getInstructionAt(a);
                for (int i = 0; i < 60 && ins != null; i++) {
                    w.println("  " + ins.getAddress() + "  " + ins);
                    ins = ins.getNext();
                }
                w.println();
                continue;
            }
            if (f == null) { w.println(); continue; }
            DecompileResults r = di.decompileFunction(f, 120, monitor);
            if (r != null && r.getDecompiledFunction() != null) {
                w.println(r.getDecompiledFunction().getC());
            } else {
                w.println("ERR " + (r == null ? "null" : r.getErrorMessage()));
            }
            w.println();
        }
        w.close();
        di.dispose();
    }
}
