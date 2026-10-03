using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Common
{
    public static class PrimeGenerator
    {
        public static List<int> GeneratePrime()
        {
            var list = new List<int>(64);
            for (int i = 2; list.Count < 64; i++)
            {
                if (IsPrime(i))
                {
                    list.Add(i);
                }
            }
            return list;

        }
        public static bool IsPrime(int n)
        {
            if (n < 2) return false;
            if (n < 4) return true;
            if (n % 3 == 0 || n % 2 == 0) return false;
            for (int d = 5; d * d <= n; d += 6)
            {
                if (n % d == 0 || n % (d + 2) == 0)
                {
                    return false;
                }
            }
            return true;
        }
    }
}