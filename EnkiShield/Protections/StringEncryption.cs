using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

using OpCodes = dnlib.DotNet.Emit.OpCodes;

namespace EnkiShield.Protections
{
    public static class StringEncryption
    {
        private static readonly Random Rng = new Random();
        private static MethodDef DecryptorMethod;

        public static void Execute(ModuleDefMD module)
        {
            Console.WriteLine("[*] Injecting AES-XOR Hybrid Encryption...");
            InjectDecryptor(module);

            foreach (TypeDef type in module.GetTypes())
            {
                if (type.IsGlobalModuleType) continue;

                // [CRITICAL] Skip Loader Classes
                if (type.Methods.Any(m => m.Name == "Attach" || m.Name == "Initialize")) continue;

                foreach (MethodDef method in type.Methods)
                {
                    if (!method.HasBody) continue;
                    if (method == DecryptorMethod) continue;

                    // [CRITICAL FIX] Skip Main for stability
                    if (method.Name == "Main") continue;

                    ProcessMethod(method);
                }
            }
        }

        private static void ProcessMethod(MethodDef method)
        {
            var instrs = method.Body.Instructions;
            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode != OpCodes.Ldstr) continue;
                string original = instrs[i].Operand as string;
                if (string.IsNullOrEmpty(original)) continue;

                byte[] key = RandomBytes(32);
                byte[] iv = RandomBytes(16);
                string encrypted = HostEncrypt(original, key, iv);
                int xorKey = Rng.Next(1, 255);
                string xorKeyStr = XorBytes(key, xorKey);
                string xorIvStr = XorBytes(iv, xorKey);

                instrs[i].OpCode = OpCodes.Ldstr;
                instrs[i].Operand = encrypted;

                instrs.Insert(i + 1, OpCodes.Ldstr.ToInstruction(xorKeyStr));
                instrs.Insert(i + 2, OpCodes.Ldstr.ToInstruction(xorIvStr));
                instrs.Insert(i + 3, OpCodes.Ldc_I4.ToInstruction(xorKey));
                instrs.Insert(i + 4, OpCodes.Call.ToInstruction(DecryptorMethod));

                i += 4;
            }
            method.Body.SimplifyMacros(method.Parameters);
            method.Body.OptimizeMacros();
        }

        private static void InjectDecryptor(ModuleDefMD module)
        {
            DecryptorMethod = new MethodDefUser("HybridDecrypt",
                MethodSig.CreateStatic(module.CorLibTypes.String,
                    module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.String, module.CorLibTypes.Int32),
                MethodAttributes.Public | MethodAttributes.Static);

            module.GlobalType.Methods.Add(DecryptorMethod);
            var body = new CilBody { InitLocals = true };
            DecryptorMethod.Body = body;

            var mscorlib = module.CorLibTypes.AssemblyRef;
            var convert = new TypeRefUser(module, "System", "Convert", mscorlib);
            var fromBase64 = new MemberRefUser(module, "FromBase64String", MethodSig.CreateStatic(new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.String), convert);
            var symmAlgo = new TypeRefUser(module, "System.Security.Cryptography", "SymmetricAlgorithm", mscorlib);
            var createAlgo = new MemberRefUser(module, "Create", MethodSig.CreateStatic(new ClassSig(symmAlgo), module.CorLibTypes.String), symmAlgo);
            var encoding = new TypeRefUser(module, "System.Text", "Encoding", mscorlib);
            var getUtf8 = new MemberRefUser(module, "get_UTF8", MethodSig.CreateStatic(new ClassSig(encoding)), encoding);
            var getString = new MemberRefUser(module, "GetString", MethodSig.CreateInstance(module.CorLibTypes.String, new SZArraySig(module.CorLibTypes.Byte)), encoding);
            var setKey = new MemberRefUser(module, "set_Key", MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Byte)), symmAlgo);
            var setIV = new MemberRefUser(module, "set_IV", MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Byte)), symmAlgo);
            var createDecryptor = new MemberRefUser(module, "CreateDecryptor", MethodSig.CreateInstance(new ClassSig(new TypeRefUser(module, "System.Security.Cryptography", "ICryptoTransform", mscorlib))), symmAlgo);
            var msType = new TypeRefUser(module, "System.IO", "MemoryStream", mscorlib);
            var msCtor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void), msType);
            var msToArray = new MemberRefUser(module, "ToArray", MethodSig.CreateInstance(new SZArraySig(module.CorLibTypes.Byte)), msType);

            var csType = new TypeRefUser(module, "System.Security.Cryptography", "CryptoStream", mscorlib);
            var csMode = new TypeRefUser(module, "System.Security.Cryptography", "CryptoStreamMode", mscorlib);
            var csCtor = new MemberRefUser(module, ".ctor", MethodSig.CreateInstance(module.CorLibTypes.Void, new ClassSig(new TypeRefUser(module, "System.IO", "Stream", mscorlib)), new ClassSig(new TypeRefUser(module, "System.Security.Cryptography", "ICryptoTransform", mscorlib)), new ValueTypeSig(csMode)), csType);
            var csWrite = new MemberRefUser(module, "Write", MethodSig.CreateInstance(module.CorLibTypes.Void, new SZArraySig(module.CorLibTypes.Byte), module.CorLibTypes.Int32, module.CorLibTypes.Int32), csType);
            var csFlush = new MemberRefUser(module, "FlushFinalBlock", MethodSig.CreateInstance(module.CorLibTypes.Void), csType);

            var aes = new Local(new ClassSig(symmAlgo));
            var ms = new Local(new ClassSig(msType));
            var cs = new Local(new ClassSig(csType));
            var keyBytes = new Local(new SZArraySig(module.CorLibTypes.Byte));
            var ivBytes = new Local(new SZArraySig(module.CorLibTypes.Byte));
            var dataBytes = new Local(new SZArraySig(module.CorLibTypes.Byte));
            var i = new Local(module.CorLibTypes.Int32);

            body.Variables.Add(aes); body.Variables.Add(ms); body.Variables.Add(cs);
            body.Variables.Add(keyBytes); body.Variables.Add(ivBytes); body.Variables.Add(dataBytes); body.Variables.Add(i);

            var il = body.Instructions;

            il.Add(OpCodes.Ldarg_0.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(fromBase64)); il.Add(OpCodes.Stloc.ToInstruction(dataBytes));
            il.Add(OpCodes.Ldarg_1.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(fromBase64)); il.Add(OpCodes.Stloc.ToInstruction(keyBytes));
            il.Add(OpCodes.Ldarg_2.ToInstruction()); il.Add(OpCodes.Call.ToInstruction(fromBase64)); il.Add(OpCodes.Stloc.ToInstruction(ivBytes));

            InjectXorLoop(il, keyBytes, i, module);
            InjectXorLoop(il, ivBytes, i, module);

            il.Add(OpCodes.Ldstr.ToInstruction("Rijndael")); il.Add(OpCodes.Call.ToInstruction(createAlgo)); il.Add(OpCodes.Stloc.ToInstruction(aes));
            il.Add(OpCodes.Ldloc.ToInstruction(aes)); il.Add(OpCodes.Ldloc.ToInstruction(keyBytes)); il.Add(OpCodes.Callvirt.ToInstruction(setKey));
            il.Add(OpCodes.Ldloc.ToInstruction(aes)); il.Add(OpCodes.Ldloc.ToInstruction(ivBytes)); il.Add(OpCodes.Callvirt.ToInstruction(setIV));

            il.Add(OpCodes.Newobj.ToInstruction(msCtor)); il.Add(OpCodes.Stloc.ToInstruction(ms));
            il.Add(OpCodes.Ldloc.ToInstruction(ms)); il.Add(OpCodes.Ldloc.ToInstruction(aes)); il.Add(OpCodes.Callvirt.ToInstruction(createDecryptor));
            il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Newobj.ToInstruction(csCtor)); il.Add(OpCodes.Stloc.ToInstruction(cs));

            il.Add(OpCodes.Ldloc.ToInstruction(cs)); il.Add(OpCodes.Ldloc.ToInstruction(dataBytes)); il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Ldloc.ToInstruction(dataBytes)); il.Add(OpCodes.Ldlen.ToInstruction()); il.Add(OpCodes.Conv_I4.ToInstruction()); il.Add(OpCodes.Callvirt.ToInstruction(csWrite));
            il.Add(OpCodes.Ldloc.ToInstruction(cs)); il.Add(OpCodes.Callvirt.ToInstruction(csFlush));

            il.Add(OpCodes.Call.ToInstruction(getUtf8)); il.Add(OpCodes.Ldloc.ToInstruction(ms)); il.Add(OpCodes.Callvirt.ToInstruction(msToArray)); il.Add(OpCodes.Callvirt.ToInstruction(getString)); il.Add(OpCodes.Ret.ToInstruction());
        }

        private static void InjectXorLoop(System.Collections.Generic.IList<Instruction> il, Local targetArray, Local iterator, ModuleDefMD mod)
        {
            var head = OpCodes.Nop.ToInstruction();
            var cond = OpCodes.Nop.ToInstruction();
            il.Add(OpCodes.Ldc_I4_0.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(iterator)); il.Add(OpCodes.Br.ToInstruction(cond));
            il.Add(head); il.Add(OpCodes.Ldloc.ToInstruction(targetArray)); il.Add(OpCodes.Ldloc.ToInstruction(iterator)); il.Add(OpCodes.Ldloc.ToInstruction(targetArray)); il.Add(OpCodes.Ldloc.ToInstruction(iterator)); il.Add(OpCodes.Ldelem_U1.ToInstruction()); il.Add(OpCodes.Ldarg_3.ToInstruction()); il.Add(OpCodes.Xor.ToInstruction()); il.Add(OpCodes.Conv_U1.ToInstruction()); il.Add(OpCodes.Stelem_I1.ToInstruction());
            il.Add(OpCodes.Ldloc.ToInstruction(iterator)); il.Add(OpCodes.Ldc_I4_1.ToInstruction()); il.Add(OpCodes.Add.ToInstruction()); il.Add(OpCodes.Stloc.ToInstruction(iterator));
            il.Add(cond); il.Add(OpCodes.Ldloc.ToInstruction(iterator)); il.Add(OpCodes.Ldloc.ToInstruction(targetArray)); il.Add(OpCodes.Ldlen.ToInstruction()); il.Add(OpCodes.Conv_I4.ToInstruction()); il.Add(OpCodes.Blt.ToInstruction(head));
        }

        private static string HostEncrypt(string s, byte[] key, byte[] iv)
        {
            using (var algo = new RijndaelManaged()) { algo.Key = key; algo.IV = iv; using (var ms = new MemoryStream()) using (var cs = new CryptoStream(ms, algo.CreateEncryptor(), CryptoStreamMode.Write)) { byte[] b = Encoding.UTF8.GetBytes(s); cs.Write(b, 0, b.Length); cs.Close(); return Convert.ToBase64String(ms.ToArray()); } }
        }
        private static string XorBytes(byte[] data, int key) { byte[] result = new byte[data.Length]; for (int i = 0; i < data.Length; i++) result[i] = (byte)(data[i] ^ key); return Convert.ToBase64String(result); }
        private static byte[] RandomBytes(int n) { var b = new byte[n]; Rng.NextBytes(b); return b; }
    }
}