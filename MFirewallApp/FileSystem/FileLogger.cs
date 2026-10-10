using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.FileSystem
{
    public static class FileLogger
    {
        public static void ClearLogFile()
        {
            File.WriteAllText("/home/denis/Documents/Kursovie/Security/MFirewallApp/FileSystem/log.txt", "");
        }
        public static void AppendLogFile(string log)
        {
            File.AppendAllText("/home/denis/Documents/Kursovie/Security/MFirewallApp/FileSystem/log.txt", BuildLog(log));
        }

        private static string BuildLog(string log) => $"[{DateTime.UtcNow.ToString("dd-MM-yyyy")}]: {log}\n";
       
    }
}