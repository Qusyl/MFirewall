using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.FileSystem
{
    public static class FileLogger
    {
        public static void AppendLogFile(string log)
        {
            File.AppendAllText("Logs/log.txt", BuildLog(log));
        }

        private static string BuildLog(string log) => $"[{DateTime.UtcNow.ToString("dd-MM-yyyy")}]: {log}";
       
    }
}