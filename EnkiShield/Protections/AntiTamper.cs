using dnlib.DotNet;
using dnlib.DotNet.Emit;
using System;
using System.Linq;
using System.Runtime.InteropServices;

using OpCodes = dnlib.DotNet.Emit.OpCodes;

namespace EnkiShield.Protections
{
    public static class AntiTamper
    {
        public static void Execute(ModuleDefMD module)
        {
            Console.WriteLine("[*] Injecting Native Anti-Tamper (Stability Fixed)...");

            var nativeType = new TypeDefUser("System.Internal", "Native", module.CorLibTypes.Object.TypeDefOrRef);
            nativeType.Attributes = TypeAttributes.NotPublic | TypeAttributes.Sealed;
            module.Types.Add(nativeType);

            var getCurrentProcess = CreatePInvoke(module, nativeType, "kernel32.dll", "GetCurrentProcess", module.CorLibTypes.IntPtr);
            var ntQuery = CreatePInvoke(module, nativeType, "ntdll.dll", "NtQueryInformationProcess",
                module.CorLibTypes.Int32, module.CorLibTypes.IntPtr, module.CorLibTypes.Int32,
                module.CorLibTypes.IntPtr, module.CorLibTypes.Int32, module.CorLibTypes.IntPtr);
            var findWindow = CreatePInvoke(module, nativeType, "user32.dll", "FindWindowA",
                module.CorLibTypes.IntPtr, module.CorLibTypes.String, module.CorLibTypes.String);

            var workerMethod = new MethodDefUser("SystemWatcher",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Object),
                MethodAttributes.Public | MethodAttributes.Static);

            module.GlobalType.Methods.Add(workerMethod);
            var body = new CilBody { InitLocals = true };
            workerMethod.Body = body;

            var mscorlib = module.CorLibTypes.AssemblyRef;
            var threadSleep = new MemberRefUser(module, "Sleep",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.Int32),
                new TypeRefUser(module, "System.Threading", "Thread", mscorlib));
            var environment = new TypeRefUser(module, "System", "Environment", mscorlib);
            var failFast = new MemberRefUser(module, "FailFast",
                MethodSig.CreateStatic(module.CorLibTypes.Void, module.CorLibTypes.String), environment);
            var marshal = new TypeRefUser(module, "System.Runtime.InteropServices", "Marshal", mscorlib);
            var allocHGlobal = new MemberRefUser(module, "AllocHGlobal",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, module.CorLibTypes.Int32), marshal);
            var readIntPtr = new MemberRefUser(module, "ReadIntPtr",
                MethodSig.CreateStatic(module.CorLibTypes.IntPtr, module.CorLibTypes.IntPtr), marshal);

            var buffer = new Local(module.CorLibTypes.IntPtr);
            var debugPort = new Local(module.CorLibTypes.IntPtr);
            body.Variables.Add(buffer);
            body.Variables.Add(debugPort);

            var il = body.Instructions;
            var loopHead = OpCodes.Nop.ToInstruction();
            var nextCheck = OpCodes.Nop.ToInstruction(); // SKIP label
            var killLabel = OpCodes.Nop.ToInstruction();

            il.Add(OpCodes.Ldc_I4.ToInstruction(8));
            il.Add(OpCodes.Call.ToInstruction(allocHGlobal));
            il.Add(OpCodes.Stloc.ToInstruction(buffer));

            il.Add(loopHead);

            // --- CHECK 1: NtQueryInformationProcess ---
            il.Add(OpCodes.Call.ToInstruction(getCurrentProcess));
            il.Add(OpCodes.Ldc_I4.ToInstruction(7)); // ProcessDebugPort
            il.Add(OpCodes.Ldloc.ToInstruction(buffer));
            il.Add(OpCodes.Ldc_I4.ToInstruction(8));
            il.Add(OpCodes.Ldc_I4_0.ToInstruction());
            il.Add(OpCodes.Conv_I.ToInstruction());
            il.Add(OpCodes.Call.ToInstruction(ntQuery));

            // [FIX] Check NTSTATUS. If != 0 (Failed), jump to nextCheck.
            // This prevents reading uninitialized memory (False Positive).
            il.Add(OpCodes.Brtrue.ToInstruction(nextCheck));

            // Call Succeeded: Read Result
            il.Add(OpCodes.Ldloc.ToInstruction(buffer));
            il.Add(OpCodes.Call.ToInstruction(readIntPtr));
            il.Add(OpCodes.Stloc.ToInstruction(debugPort));

            il.Add(OpCodes.Ldloc.ToInstruction(debugPort));
            il.Add(OpCodes.Brtrue.ToInstruction(killLabel));

            // --- CHECK 2: FindWindow ---
            il.Add(nextCheck); // Start here if Check 1 failed or passed
            il.Add(OpCodes.Ldnull.ToInstruction());
            il.Add(OpCodes.Ldstr.ToInstruction("dnSpy"));
            il.Add(OpCodes.Call.ToInstruction(findWindow));
            il.Add(OpCodes.Brtrue.ToInstruction(killLabel));

            il.Add(OpCodes.Ldc_I4.ToInstruction(1000));
            il.Add(OpCodes.Call.ToInstruction(threadSleep));
            il.Add(OpCodes.Br.ToInstruction(loopHead));

            il.Add(killLabel);
            il.Add(OpCodes.Ldstr.ToInstruction("Corrupted State."));
            il.Add(OpCodes.Call.ToInstruction(failFast));
            il.Add(OpCodes.Ret.ToInstruction());

            InjectThreadPoolStarter(module, workerMethod);
        }

        private static MethodDef CreatePInvoke(ModuleDefMD module, TypeDef owner, string dll, string func, TypeSig ret, params TypeSig[] args)
        {
            var method = new MethodDefUser(func, MethodSig.CreateStatic(ret, args));
            method.Attributes = MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.PinvokeImpl | MethodAttributes.HideBySig;
            method.ImplAttributes = MethodImplAttributes.PreserveSig;
            var modRef = new ModuleRefUser(module, dll);
            method.ImplMap = new ImplMapUser(modRef, func, PInvokeAttributes.CallConvWinapi | PInvokeAttributes.NoMangle);
            owner.Methods.Add(method);
            return method;
        }

        private static void InjectThreadPoolStarter(ModuleDefMD module, MethodDef worker)
        {
            if (module.EntryPoint == null) return;
            var entry = module.EntryPoint;
            var ins = entry.Body.Instructions;
            entry.Body.SimplifyMacros(entry.Parameters);

            var mscorlib = module.CorLibTypes.AssemblyRef;
            var threadPool = new TypeRefUser(module, "System.Threading", "ThreadPool", mscorlib);
            var waitCallback = new TypeRefUser(module, "System.Threading", "WaitCallback", mscorlib);
            var queue = new MemberRefUser(module, "QueueUserWorkItem",
                MethodSig.CreateStatic(module.CorLibTypes.Boolean, new ClassSig(waitCallback)), threadPool);
            var cctor = new MemberRefUser(module, ".ctor",
                MethodSig.CreateInstance(module.CorLibTypes.Void, module.CorLibTypes.Object, module.CorLibTypes.IntPtr), waitCallback);

            ins.Insert(0, OpCodes.Ldnull.ToInstruction());
            ins.Insert(1, OpCodes.Ldftn.ToInstruction(worker));
            ins.Insert(2, OpCodes.Newobj.ToInstruction(cctor));
            ins.Insert(3, OpCodes.Call.ToInstruction(queue));
            ins.Insert(4, OpCodes.Pop.ToInstruction());

            entry.Body.OptimizeMacros();
        }
    }
}