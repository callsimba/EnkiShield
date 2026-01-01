using dnlib.DotNet;
using dnlib.DotNet.Writer;
using System;
using System.IO;
using EnkiShield.Protections;

namespace EnkiShield
{
    internal class Program
    {
        public static ModuleDefMD Module { get; private set; }

        static void Main(string[] args)
        {
            Console.Title = "EnkiShield - Cybersecurity Final Project";
            string input = args.Length > 0 ? args[0] : AskFile();
            if (string.IsNullOrWhiteSpace(input) || !File.Exists(input)) return;

            try
            {
                Console.WriteLine($"[*] Loading: {Path.GetFileName(input)}");
                Module = ModuleDefMD.Load(input);

                // --- 1. CORE DEFENSE ---
                AntiTamper.Execute(Module);

                // --- 2. LOGIC OBFUSCATION (Order Changed for Stability) ---
                // Run OpaquePredicates FIRST. CFF will then flatten the predicates too.
                OpaquePredicates.Execute(Module);

                // --- 3. STRUCTURAL OBFUSCATION ---
                // Flattens the code (including the Opaque Predicates) into a switch loop
                ControlFlowFlattening.Execute(Module);

                // --- 4. DATA OBFUSCATION ---
                StringEncryption.Execute(Module);

                // --- 5. RENAMING ---
                Renamer.Execute(Module);

                string output = Path.Combine(
                    Path.GetDirectoryName(input),
                    Path.GetFileNameWithoutExtension(input) + "_protected.exe");

                var options = new ModuleWriterOptions(Module);
                options.MetadataOptions.Flags = MetadataFlags.PreserveAll;
                options.Logger = DummyLogger.NoThrowInstance;

                Console.WriteLine("[*] Saving...");
                Module.Write(output, options);

                Console.WriteLine($"[+] Success: {output}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Critical Error: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        private static string AskFile()
        {
            Console.Write("Drag EXE: ");
            return Console.ReadLine()?.Replace("\"", "") ?? "";
        }
    }
}