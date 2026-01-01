using dnlib.DotNet;
using System;
using System.Linq;

namespace EnkiShield.Protections
{
    public static class Renamer
    {
        private static readonly Random Rng = new Random();

        public static void Execute(ModuleDefMD module)
        {
            Console.WriteLine("[*] Renaming: Executing Network-Safe Mode...");

            foreach (TypeDef type in module.GetTypes())
            {
                if (type.IsGlobalModuleType || type.IsRuntimeSpecialName) continue;

                // [CRITICAL FIX] Do NOT rename Classes.
                // This breaks Serialization (JSON/XML) used in networking.
                // if (type.IsNotPublic) type.Name = RandomName(); <--- REMOVED

                foreach (MethodDef method in type.Methods)
                {
                    if (CanRenameMethod(method))
                        method.Name = RandomName();
                }

                foreach (FieldDef field in type.Fields)
                {
                    if (CanRenameField(field))
                        field.Name = RandomName();
                }
            }
        }

        private static bool CanRenameMethod(MethodDef m)
        {
            // Safety Checks
            if (m.IsConstructor || m.Name == "Main" || m.IsRuntimeSpecialName) return false;

            // [CRITICAL] Skip Public Methods (Interfaces/Reflection)
            if (m.IsPublic || m.IsVirtual) return false;

            // [CRITICAL] Skip Properties (get/set)
            if (m.Name.StartsWith("get_") || m.Name.StartsWith("set_")) return false;

            // [CRITICAL] Skip Async/Compiler Generated
            if (m.Name.Contains("<") || m.Name.Contains(">")) return false;

            return true;
        }

        private static bool CanRenameField(FieldDef f)
        {
            if (f.IsRuntimeSpecialName || f.IsLiteral) return false;

            // Only rename private fields to be safe
            if (f.IsPublic || f.IsFamily) return false;

            return true;
        }

        private static string RandomName()
        {
            return new string(Enumerable.Range(0, 10)
                .Select(_ => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[Rng.Next(52)])
                .ToArray());
        }
    }
}