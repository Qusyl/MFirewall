
namespace Domain.Models
{
    public abstract class Packet(string type)
    {
        public string PacketType { get; } = type;
       
    }
}