using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp.Rules.FloodRule.Detectors.Flood
{
    public sealed class PacketHistory
    {
        private readonly Lock _lock = new Lock();

        private readonly Queue<DateTimeOffset> _timestamps = new();

         public bool IsEmpty { get { lock (_lock) return _timestamps.Count == 0; } }
        

        public bool TryRegister(DateTimeOffset now, TimeSpan window, int limit)
        {
            lock (_lock)
            {
                var cutoff = now - window;

                while (_timestamps.Count > 0 && _timestamps.Peek() < cutoff)
                {
                    _timestamps.Dequeue();
                }
                if (_timestamps.Count >= limit)
                {
                    return false;
                }
                _timestamps.Enqueue(now);

                return true;
            }
        }
        public void TrimOlderThan(DateTimeOffset cutoff)
        {
            lock (_lock)
            {
                while (_timestamps.Count > 0 && _timestamps.Peek() < cutoff)
                {
                    _timestamps.Dequeue();
                }

            }
        }
     
    
    }
}