using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.FileSystem
{
    public static class FileLoader
    {
        private static string pathBase = "/home/denis/Documents/Kursovie/Security/Api/MFirewallApi/configuration";
        public static List<string> LoadBlackListDomains()
        {
            var path = Path.Combine(pathBase, "black_list.txt");

            var list = File.ReadAllLines(path).ToList();

            return list;
        }
        public static List<string> LoadAllowedListDomains()
        {
            var path = Path.Combine(pathBase, "white_list.txt");

            var list = File.ReadAllLines(path).ToList();

            return list;
        }
    }
}