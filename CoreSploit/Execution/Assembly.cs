using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;

namespace CoreSploit.Execution
{
    class Assembly
    {
        public static void AssemblyExecute(byte[] AssemblyBytes, Object[] Args = null)
        {
            /// <summary>
            /// Loads a specified .NET assembly byte array and executes the EntryPoint.
            /// </summary>
            /// <param name="AssemblyBytes">The .NET assembly byte array.</param>
            /// <param name="Args">The arguments to pass to the assembly's EntryPoint.</param>
            if (Args == null)
            {
                Args = new object[] {new string[] { }};
            }

            var asm = System.Reflection.Assembly.Load(AssemblyBytes);
            asm.EntryPoint.Invoke(null, Args);

        }
        /// <summary>
        /// Loads a specified .NET assembly byte array and executes a specified method within a
        /// specified type with specified parameters.
        /// </summary>
        /// <param name="AssemblyBytes">The .NET assembly byte array.</param>
        /// <param name="TypeName">The name of the type that contains the method to execute.</param>
        /// <param name="MethodName">The name of the method to execute.</param>
        /// <param name="Parameters">The parameters to pass to the method.</param>
        /// <returns>GenericObjectResult of the method.</returns>
        public static string AssemblyExecute(byte[] AssemblyBytes, String TypeName = "", String MethodName = "Execute", Object[] Parameters = default(Object[]))
        {
            System.Reflection.Assembly assembly = System.Reflection.Assembly.Load(AssemblyBytes);
            Type type = TypeName == "" ? assembly.GetTypes()[0] : assembly.GetType(TypeName);
            System.Reflection.MethodInfo method = MethodName == "" ? type.GetMethods()[0] : type.GetMethod(MethodName);
            string results = method.Invoke(null, Parameters).ToString();
            return results;
        }

        /// <summary>
        /// Loads a specified base64-encoded .NET assembly and executes a specified method within a
        /// specified type with specified parameters.
        /// </summary>
        /// <param name="EncodedAssembly">The base64-encoded .NET assembly byte array.</param>
        /// <param name="TypeName">The name of the type that contains the method to execute.</param>
        /// <param name="MethodName">The name of the method to execute.</param>
        /// <param name="Parameters">The parameters to pass to the method.</param>
        /// <returns>GenericObjectResult of the method.</returns>
        public static string AssemblyExecute(String EncodedAssembly, String TypeName = "", String MethodName = "Execute", Object[] Parameters = default(Object[]))
        {
            return AssemblyExecute(Convert.FromBase64String(EncodedAssembly), TypeName, MethodName, Parameters);
        }

        /// <summary>
        /// Loads a specified base64-encoded .NET assembly and executes the EntryPoint.
        /// </summary>
        /// <param name="EncodedAssembly">The base64-encoded .NET assembly byte array.</param>
        /// <param name="Args">The arguments to pass to the assembly's EntryPoint.</param>
        public static void AssemblyExecute(String EncodedAssembly, Object[] Args = default(Object[]))
        {
            AssemblyExecute(Convert.FromBase64String(EncodedAssembly), Args);
        }

        /// <summary>
        /// Loads a specified .NET assembly byte array.
        /// </summary>
        /// <param name="AssemblyBytes">The .NET assembly byte array.</param>
        /// <returns>Loaded assembly.</returns>
        public static System.Reflection.Assembly Load(byte[] AssemblyBytes)
        {
            return System.Reflection.Assembly.Load(AssemblyBytes);
        }

        /// <summary>
        /// Loads a specified .NET assembly byte array.
        /// </summary>
        /// <param name="EncodedAssembly">The base64-encoded .NET assembly byte array.</param>
        /// <returns>Loaded assembly.</returns>
        public static System.Reflection.Assembly Load(string EncodedAssembly)
        {
            return System.Reflection.Assembly.Load(Convert.FromBase64String(EncodedAssembly));
        }

    }
}
