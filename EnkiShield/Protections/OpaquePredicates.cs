using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Linq;

using OpCodes = dnlib.DotNet.Emit.OpCodes;

namespace EnkiShield.Protections
{
    public static class OpaquePredicates
    {
        private static readonly Random Rng = new Random();
        private static FieldDefUser _zeroField;

        public static void Execute(ModuleDefMD module)
        {
            _zeroField = new FieldDefUser("Internal_Check", new FieldSig(module.CorLibTypes.Int32), FieldAttributes.Public | FieldAttributes.Static);
            module.GlobalType.Fields.Add(_zeroField);

            var cctor = module.GlobalType.FindOrCreateStaticConstructor();
            cctor.Body.SimplifyMacros(cctor.Parameters);
            var instructions = cctor.Body.Instructions;

            var envType = new TypeRefUser(module, "System", "Environment", module.CorLibTypes.AssemblyRef);
            var getTickCount = new MemberRefUser(module, "get_TickCount", MethodSig.CreateStatic(module.CorLibTypes.Int32), envType);

            instructions.Insert(0, OpCodes.Call.ToInstruction(getTickCount));
            instructions.Insert(1, OpCodes.Ldc_I4_0.ToInstruction());
            instructions.Insert(2, OpCodes.And.ToInstruction());
            instructions.Insert(3, OpCodes.Stsfld.ToInstruction(_zeroField));
            if (instructions.Count == 4) instructions.Add(OpCodes.Ret.ToInstruction());
            cctor.Body.MaxStack = (ushort)Math.Max((int)cctor.Body.MaxStack, 8);
            cctor.Body.OptimizeMacros();

            foreach (TypeDef type in module.GetTypes())
            {
                if (type.IsGlobalModuleType) continue;
                if (type.Methods.Any(m => m.Name == "Attach" || m.Name == "Initialize")) continue;

                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    if (method.Name == "Main") continue;

                    // [CRITICAL FIX] Skip Async/Compiler Generated Methods
                    if (method.IsCompilerControlled || method.Name.Contains("<")) continue;

                    if (method.Body.Instructions.Count < 10) continue;
                    if (method.IsConstructor) continue;
                    InjectPredicates(method);
                }
            }
        }

        private static void InjectPredicates(MethodDef method)
        {
            var instructions = method.Body.Instructions;
            for (int i = instructions.Count - 1; i > 0; i--)
            {
                if (Rng.Next(0, 100) > 15) continue;
                InsertRuntimePredicate(method, i);
            }
            method.Body.SimplifyMacros(method.Parameters);
            method.Body.OptimizeMacros();
        }

        private static void InsertRuntimePredicate(MethodDef method, int index)
        {
            var instrs = method.Body.Instructions;
            var target = instrs[index];
            int randomVal = Rng.Next(100, 99999);

            instrs.Insert(index + 0, OpCodes.Ldc_I4.ToInstruction(randomVal));
            instrs.Insert(index + 1, OpCodes.Ldsfld.ToInstruction(_zeroField));
            instrs.Insert(index + 2, OpCodes.Mul.ToInstruction());
            instrs.Insert(index + 3, OpCodes.Brfalse.ToInstruction(target));
            instrs.Insert(index + 4, OpCodes.Ldnull.ToInstruction());
            instrs.Insert(index + 5, OpCodes.Throw.ToInstruction());
        }
    }
}