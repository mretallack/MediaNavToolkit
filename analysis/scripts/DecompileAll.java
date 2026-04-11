// Decompile all functions to pseudo-C output file
// @category Headless
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String output = args.length > 0 ? args[0] : currentProgram.getName() + "_decompiled.c";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FileWriter fw = new FileWriter(output);
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        int count = 0;
        while (funcs.hasNext()) {
            Function func = funcs.next();
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                if (code != null) {
                    fw.write(code);
                    fw.write("\n");
                    count++;
                }
            }
        }
        fw.close();
        decomp.dispose();
        println("[*] Decompiled " + count + " functions -> " + output);
    }
}
