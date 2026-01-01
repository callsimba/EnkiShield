using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.Linq;

namespace EnkiShield.Protections
{
    public static class ControlFlowFlattening
    {
        private static readonly Random Rng = new Random();

        public static void Execute(ModuleDefMD module)
        {
            Console.WriteLine("[*] Injecting Control Flow Flattening (Async-Safe)...");

            foreach (TypeDef type in module.GetTypes())
            {
                if (type.IsGlobalModuleType) continue;

                // Skip Costura/Fody Loaders
                if (type.Methods.Any(m => m.Name == "Attach" || m.Name == "Initialize")) continue;
                // [NEW] Skip Compiler Generated Classes (Async State Machines / Lambdas)
                if (type.CustomAttributes.Any(a => a.TypeFullName.Contains("CompilerGenerated"))) continue;

                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody || !method.Body.HasInstructions) continue;

                    // --- STABILITY FILTERS ---

                    // 1. Skip Entry Point
                    if (method.Name == "Main") continue;

                    // 2. [CRITICAL FIX] Skip Async/Compiler Generated Methods
                    // Flattening these breaks 'await', causing networking to hang.
                    if (method.IsCompilerControlled || method.Name.Contains("<") || method.Name.Contains(">")) continue;
                    if (method.CustomAttributes.Any(a => a.TypeFullName.Contains("CompilerGenerated"))) continue;

                    // 3. Standard Skips
                    if (method.IsConstructor) continue;
                    if (method.Name.StartsWith("get_") || method.Name.StartsWith("set_")) continue;
                    if (method.Body.ExceptionHandlers.Count > 0) continue;
                    if (method.Body.Instructions.Count < 20) continue;
                    if (method.HasGenericParameters || method.IsPinvokeImpl) continue;

                    FlattenMethod(method);
                }
            }
        }

        private static void FlattenMethod(MethodDef method)
        {
            method.Body.SimplifyMacros(method.Parameters);
            var body = method.Body;
            var instructions = body.Instructions;

            // 1. Identify Targets
            var targets = new HashSet<Instruction>();
            foreach (var instr in instructions)
            {
                if (instr.Operand is Instruction target) targets.Add(target);
                else if (instr.Operand is Instruction[] targetArray)
                    foreach (var t in targetArray) targets.Add(t);
            }

            // 2. Build Blocks
            var blocks = new List<BasicBlock>();
            var currentBlock = new BasicBlock { Id = 0 };
            blocks.Add(currentBlock);
            int blockIdCounter = 1;

            for (int i = 0; i < instructions.Count; i++)
            {
                var instr = instructions[i];
                if (i > 0 && targets.Contains(instr))
                {
                    var newBlock = new BasicBlock { Id = blockIdCounter++ };
                    currentBlock.NextBlockId = newBlock.Id;
                    blocks.Add(newBlock);
                    currentBlock = newBlock;
                }
                currentBlock.Instructions.Add(instr);

                if (instr.OpCode.FlowControl == FlowControl.Branch ||
                    instr.OpCode.FlowControl == FlowControl.Cond_Branch ||
                    instr.OpCode.FlowControl == FlowControl.Return ||
                    instr.OpCode.FlowControl == FlowControl.Throw)
                {
                    if (i + 1 < instructions.Count)
                    {
                        var newBlock = new BasicBlock { Id = blockIdCounter++ };
                        currentBlock.NextBlockId = newBlock.Id;
                        blocks.Add(newBlock);
                        currentBlock = newBlock;
                    }
                }
            }

            // 3. Reconstruct
            var shuffledBlocks = blocks.OrderBy(x => Rng.Next()).ToList();
            instructions.Clear();
            body.InitLocals = true;
            var localState = new Local(method.Module.CorLibTypes.Int32);
            body.Variables.Add(localState);
            var switchTarget = OpCodes.Nop.ToInstruction();
            var switchInstr = OpCodes.Switch.ToInstruction(new Instruction[0]);

            instructions.Add(OpCodes.Ldc_I4.ToInstruction(blocks[0].Id));
            instructions.Add(OpCodes.Stloc.ToInstruction(localState));
            instructions.Add(switchTarget);
            instructions.Add(OpCodes.Ldloc.ToInstruction(localState));
            instructions.Add(switchInstr);

            var caseLabels = new Instruction[blockIdCounter];

            foreach (var block in shuffledBlocks)
            {
                var blockLabel = OpCodes.Nop.ToInstruction();
                caseLabels[block.Id] = blockLabel;
                instructions.Add(blockLabel);

                foreach (var instr in block.Instructions)
                {
                    if (instr.OpCode.FlowControl == FlowControl.Cond_Branch)
                    {
                        var targetInstr = instr.Operand as Instruction;
                        int targetId = GetBlockId(blocks, targetInstr);
                        int nextId = block.NextBlockId;
                        var jumpToTarget = OpCodes.Nop.ToInstruction();
                        instructions.Add(Instruction.Create(instr.OpCode, jumpToTarget));
                        instructions.Add(OpCodes.Ldc_I4.ToInstruction(nextId));
                        instructions.Add(OpCodes.Stloc.ToInstruction(localState));
                        instructions.Add(OpCodes.Br.ToInstruction(switchTarget));
                        instructions.Add(jumpToTarget);
                        instructions.Add(OpCodes.Ldc_I4.ToInstruction(targetId));
                        instructions.Add(OpCodes.Stloc.ToInstruction(localState));
                        instructions.Add(OpCodes.Br.ToInstruction(switchTarget));
                    }
                    else if (instr.OpCode.FlowControl == FlowControl.Branch)
                    {
                        var targetInstr = instr.Operand as Instruction;
                        int targetId = GetBlockId(blocks, targetInstr);
                        instructions.Add(OpCodes.Ldc_I4.ToInstruction(targetId));
                        instructions.Add(OpCodes.Stloc.ToInstruction(localState));
                        instructions.Add(OpCodes.Br.ToInstruction(switchTarget));
                    }
                    else if (instr.OpCode.FlowControl == FlowControl.Return || instr.OpCode.FlowControl == FlowControl.Throw)
                    {
                        instructions.Add(instr);
                    }
                    else instructions.Add(instr);
                }
                var last = block.Instructions.LastOrDefault();
                if (last != null && last.OpCode.FlowControl != FlowControl.Branch && last.OpCode.FlowControl != FlowControl.Cond_Branch && last.OpCode.FlowControl != FlowControl.Return && last.OpCode.FlowControl != FlowControl.Throw)
                {
                    instructions.Add(OpCodes.Ldc_I4.ToInstruction(block.NextBlockId));
                    instructions.Add(OpCodes.Stloc.ToInstruction(localState));
                    instructions.Add(OpCodes.Br.ToInstruction(switchTarget));
                }
            }
            switchInstr.Operand = caseLabels;
            body.MaxStack += 8;
            body.OptimizeBranches();
            body.SimplifyBranches();
        }

        private static int GetBlockId(List<BasicBlock> blocks, Instruction target)
        {
            var block = blocks.FirstOrDefault(b => b.Instructions.Contains(target));
            return block?.Id ?? 0;
        }

        private class BasicBlock
        {
            public int Id;
            public int NextBlockId;
            public List<Instruction> Instructions = new List<Instruction>();
        }
    }
}