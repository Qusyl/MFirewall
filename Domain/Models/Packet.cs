
namespace Domain.Models
{
    public abstract class Packet(uint Id)
    {
        public uint Id { get; set; } = Id;
    }
}