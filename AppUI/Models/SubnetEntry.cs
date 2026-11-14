using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace MFirewallAppUI.Models
{
    public class SubnetEntry
    {
    public string Ip { get; set; } = "";
    public int Mask { get; set; }

    public override string ToString() => $"{Ip}/{Mask}";

   
    public bool IsValid(out string? error)
    {
        error = null;

        if (!IPAddress.TryParse(Ip, out var addr))
        {
            error = "Некорректный IP";
            return false;
        }

        if (Mask < 0 || Mask > 32)
        {
            error = "Маска должна быть от 0 до 32";
            return false;
        }

        
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && Mask > 128)
        {
            error = "Для IPv6 маска от 0 до 128";
            return false;
        }

        return true;
    }
    }
}