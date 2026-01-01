using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using OpCodes = dnlib.DotNet.Emit.OpCodes;
using MethodAttributes = dnlib.DotNet.MethodAttributes;
using MethodImplAttributes = dnlib.DotNet.MethodImplAttributes;
using FieldAttributes = dnlib.DotNet.FieldAttributes;

namespace EnkiShield
{
    internal class Program
    {
        private static readonly Random Rng = new Random();
        private static ModuleDefMD _module;

        private static readonly List<byte> GlobalBlob = new List<byte>();
        private static FieldDef GlobalBlobField;
        private static MethodDef GlobalStringDecryptor;

        static void Main(string[] args)
        {
            Console.Title = "EnkiShield – SAFE MODE (C# 7.3)";
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[*] SAFE OBFUSCATION – NETWORK SAFE");
            Console.ResetColor();

            string inputPath = string.Empty;

            if (args.Length > 0)
            {
                inputPath = args[0];
            }
            else
            {
                Console.Write("[?] Drag enki_client.exe: ");
                string line = Console.ReadLine();
                if (line != null)
                    inputPath = line.Replace("\"", "");
            }

            if (string.IsNullOrWhiteSpace(inputPath) || !File.Exists(inputPath))
                return;

            try
            {
                _module = ModuleDefMD.Load(inputPath);

                PrepareGlobalStringStorage();

                int renamedTypes = 0;
                int processedMethods = 0;

                foreach (TypeDef type in _module.GetTypes())
                {
                    if (!CanRenameType(type))
                        continue;

                    type.Name = RandomName();
                    type.Namespace = "";
                    renamedTypes++;

                    foreach (FieldDef field in type.Fields)
                        if (!field.IsRuntimeSpecialName)
                            field.Name = RandomName();

                    foreach (PropertyDef prop in type.Properties)
                        prop.Name = RandomName();

                    foreach (EventDef evt in type.Events)
                        evt.Name = RandomName();

                    foreach (MethodDef method in type.Methods)
                    {
                        if (!CanProcessMethod(method))
                            continue;

                        method.Name = RandomName();
                        ProcessStrings(method);
                        processedMethods++;
                    }
                }

                InjectGlobalBlob();

                string outputPath =
                    Path.Combine(
                        Path.GetDirectoryName(inputPath),
                        Path.GetFileNameWithoutExtension(inputPath) + "_protected.exe");

                var opts = new dnlib.DotNet.Writer.ModuleWriterOptions(_module);
                opts.Logger = DummyLogger.NoThrowInstance;
                opts.MetadataOptions.Flags = dnlib.DotNet.Writer.MetadataFlags.PreserveAll;

                _module.Write(outputPath, opts);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[SUCCESS]");
                Console.WriteLine(" Types renamed: " + renamedTypes);
                Console.WriteLine(" Methods processed: " + processedMethods);
                Console.WriteLine(" String bytes: " + GlobalBlob.Count);
                Console.WriteLine(" Output: " + Path.GetFileName(outputPath));
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[CRITICAL ERROR]");
                Console.WriteLine(ex);
                Console.ResetColor();
            }

            Console.ReadKey();
        }

        // =========================================================
        // STRING STORAGE
        // =========================================================

        private static void PrepareGlobalStringStorage()
        {
            var byteArraySig = new SZArraySig(_module.CorLibTypes.Byte);

            GlobalBlobField = new FieldDefUser(
                RandomName(),
                new FieldSig(byteArraySig),
                FieldAttributes.Public | FieldAttributes.Static);

            _module.GlobalType.Fields.Add(GlobalBlobField);

            GlobalStringDecryptor = new MethodDefUser(
                RandomName(),
                MethodSig.CreateStatic(
                    _module.CorLibTypes.String,
                    _module.CorLibTypes.Int32,
                    _module.CorLibTypes.Int32),
                MethodImplAttributes.IL | MethodImplAttributes.Managed,
                MethodAttributes.Public | MethodAttributes.Static);

            _module.GlobalType.Methods.Add(GlobalStringDecryptor);

            CilBody body = new CilBody();
            body.InitLocals = true;
            GlobalStringDecryptor.Body = body;

            var encodingType =
                _module.CorLibTypes.GetTypeRef("System.Text", "Encoding");

            var getUtf8 = new MemberRefUser(
                _module,
                "get_UTF8",
                MethodSig.CreateStatic(new ClassSig(encodingType)),
                encodingType);

            var getString = new MemberRefUser(
                _module,
                "GetString",
                MethodSig.CreateInstance(
                    _module.CorLibTypes.String,
                    new SZArraySig(_module.CorLibTypes.Byte),
                    _module.CorLibTypes.Int32,
                    _module.CorLibTypes.Int32),
                encodingType);

            body.Instructions.Add(OpCodes.Call.ToInstruction(getUtf8));
            body.Instructions.Add(OpCodes.Ldsfld.ToInstruction(GlobalBlobField));
            body.Instructions.Add(OpCodes.Ldarg_0.ToInstruction());
            body.Instructions.Add(OpCodes.Ldarg_1.ToInstruction());
            body.Instructions.Add(OpCodes.Callvirt.ToInstruction(getString));
            body.Instructions.Add(OpCodes.Ret.ToInstruction());
        }

        private static void ProcessStrings(MethodDef method)
        {
            if (!method.HasBody)
                return;

            var instrs = method.Body.Instructions;

            for (int i = 0; i < instrs.Count; i++)
            {
                if (instrs[i].OpCode != OpCodes.Ldstr)
                    continue;

                string value = instrs[i].Operand as string;
                if (string.IsNullOrEmpty(value))
                    continue;

                byte[] data = Encoding.UTF8.GetBytes(value);
                int index = GlobalBlob.Count;

                GlobalBlob.AddRange(data);

                instrs[i].OpCode = OpCodes.Ldc_I4;
                instrs[i].Operand = index;

                instrs.Insert(i + 1, OpCodes.Ldc_I4.ToInstruction(data.Length));
                instrs.Insert(i + 2, OpCodes.Call.ToInstruction(GlobalStringDecryptor));

                i += 2;
            }
        }

        private static void InjectGlobalBlob()
        {
            if (GlobalBlob.Count == 0)
                return;

            MethodDef cctor = _module.GlobalType.FindOrCreateStaticConstructor();

            var convertType =
                _module.CorLibTypes.GetTypeRef("System", "Convert");

            var fromBase64 = new MemberRefUser(
                _module,
                "FromBase64String",
                MethodSig.CreateStatic(
                    new SZArraySig(_module.CorLibTypes.Byte),
                    _module.CorLibTypes.String),
                convertType);

            string b64 = Convert.ToBase64String(GlobalBlob.ToArray());

            var instrs = cctor.Body.Instructions;
            instrs.Insert(0, OpCodes.Ldstr.ToInstruction(b64));
            instrs.Insert(1, OpCodes.Call.ToInstruction(fromBase64));
            instrs.Insert(2, OpCodes.Stsfld.ToInstruction(GlobalBlobField));
        }

        // =========================================================
        // SAFETY RULES
        // =========================================================

        private static bool CanRenameType(TypeDef type)
        {
            if (type.IsGlobalModuleType)
                return false;

            if (type.Name.StartsWith("<"))
                return false;

            if (type.CustomAttributes.Any(a =>
                a.TypeFullName.Contains("CompilerGenerated")))
                return false;

            if (type.Namespace.Contains("Shared") ||
                type.Namespace.Contains("Packets") ||
                type.Name.Contains("Packet") ||
                type.Name.Contains("Socket") ||
                type.Name.Contains("Config") ||
                type.Name.Contains("Program") ||
                type.Name.Contains("Plugin"))
                return false;

            return true;
        }

        private static bool CanProcessMethod(MethodDef method)
        {
            if (!method.HasBody)
                return false;

            if (method.IsConstructor ||
                method.IsRuntimeSpecialName ||
                method.IsVirtual ||
                method.Name == "Main")
                return false;

            if (method.Body.ExceptionHandlers.Count > 0)
                return false;

            return true;
        }

        private static string RandomName()
        {
            const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            char[] buffer = new char[10];

            for (int i = 0; i < buffer.Length; i++)
                buffer[i] = chars[Rng.Next(chars.Length)];

            return new string(buffer);
        }
    }
}
