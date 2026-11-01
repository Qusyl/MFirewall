using System.Collections.Concurrent;
using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Interface;
using MFirewallApp.Rules.PortScanRule.Options;
using MFirewallApp.Verdict;

namespace MFirewallApp.Rules.RateLimitRule
{
    public class RateLimitRule : IPacketRule
    {
        public string RuleName => "rate_limit_rule";

        public int RuleScore => 100;

        private readonly ConcurrentDictionary<
            RateLimitKey,
            FixedWindowState> _windowStorage = new();

        private readonly ConcurrentDictionary<
            RateLimitKey,
            TokenBucketState> _bucketStorage = new();


        public PacketDecision Check(
            IPv4Packet packet,
            FirewallProtection configuration)
        {
            var options = configuration.RateLimitOptions;

            if (!options.Enable)
            {
                return NoMatch(packet, "Rate limiting disabled");
            }

            if (options.Algorithm == RateLimitAlgorithm.FIXED_WINDOW)
            {
                return FixedWindow(packet, options);
            }

            if (!options.TokenBucket.Enable)
            {
                return NoMatch(packet, "Token bucket disabled");
            }

            return TokenBucket(packet, options);
        }


  
        private PacketDecision FixedWindow(
            IPv4Packet packet,
            RateLimitOptions options)
        {
            var exceededRules = new List<string>();

            var now = DateTimeOffset.UtcNow;

            
            if (options.Ip.Enable)
            {
                var key = new RateLimitKey(
                    RateLimitScope.IP,
                    packet.Header.SourceAddress.ToString());

                if (IsFixedWindowExceeded(
                    key,
                    options.Ip.MaxPackets,
                    options.Ip.WindowSeconds,
                    now))
                {
                    exceededRules.Add("IP");
                }
            }

         
            var transportPacket = packet.ExtractPacket();

            ushort? destinationPort = transportPacket switch
            {
                UdpPacket udp => udp.Header.DestinationPort,
                TcpPacket tcp => tcp.Header.DestinationPort,
                _ => null
            };

          
            if (options.Port.Enable && destinationPort.HasValue)
            {
                var key = new RateLimitKey(
                    RateLimitScope.PORT,
                    destinationPort.Value.ToString());

                if (IsFixedWindowExceeded(
                    key,
                    options.Port.MaxPackets,
                    options.Port.WindowSeconds,
                    now))
                {
                    exceededRules.Add("PORT");
                }
            }

            if (options.Protocol.Enable)
            {
                var key = new RateLimitKey(
                    RateLimitScope.PROTOCOL,
                    packet.Header.Protocol.ToString());

                if (IsFixedWindowExceeded(
                    key,
                    options.Protocol.MaxPackets,
                    options.Protocol.WindowSeconds,
                    now))
                {
                    exceededRules.Add("PROTOCOL");
                }
            }

            if (exceededRules.Count > 0)
            {
                return new PacketDecision(
                    packet.Header.Identification,
                    Verdict.Verdict.DROP,
                    $"Rate limit exceeded: {string.Join(", ", exceededRules)}",
                    RuleName);
            }

            return NoMatch(packet, "Fixed Window limit not exceeded");
        }


        private bool IsFixedWindowExceeded(
            RateLimitKey key,
            int maxPackets,
            int windowSeconds,
            DateTimeOffset now)
        {
            var state = _windowStorage.GetOrAdd(
                key,
                _ => new FixedWindowState
                {
                    WindowStart = now,
                    PacketCount = 0
                });

            lock (state.syncRoot)
            {
               
                if (now >= state.WindowStart.AddSeconds(windowSeconds))
                {
                   
                    state.WindowStart = now;
                    state.PacketCount = 0;
                }

                state.PacketCount++;

                Console.WriteLine(
                    $"[FIXED WINDOW] Key={key}, " +
                    $"Count={state.PacketCount}/{maxPackets}");

                return state.PacketCount > maxPackets;
            }
        }



        private PacketDecision TokenBucket(
            IPv4Packet packet,
            RateLimitOptions options)
        {
            var exceededRules = new List<string>();

            var now = DateTimeOffset.UtcNow;

            var transportPacket = packet.ExtractPacket();

            ushort? destinationPort = transportPacket switch
            {
                UdpPacket udp => udp.Header.DestinationPort,
                TcpPacket tcp => tcp.Header.DestinationPort,
                _ => null
            };

            
            if (options.Ip.Enable)
            {
                var key = new RateLimitKey(
                    RateLimitScope.IP,
                    packet.Header.SourceAddress.ToString());

                if (!TryConsumeToken(key, options.TokenBucket, now))
                {
                    exceededRules.Add("IP");
                }
            }

       
            if (options.Port.Enable && destinationPort.HasValue)
            {
                var key = new RateLimitKey(
                    RateLimitScope.PORT,
                    destinationPort.Value.ToString());

                if (!TryConsumeToken(key, options.TokenBucket, now))
                {
                    exceededRules.Add("PORT");
                }
            }

            
            if (options.Protocol.Enable)
            {
                var key = new RateLimitKey(
                    RateLimitScope.PROTOCOL,
                    packet.Header.Protocol.ToString());

                if (!TryConsumeToken(key, options.TokenBucket, now))
                {
                    exceededRules.Add("PROTOCOL");
                }
            }

            if (exceededRules.Count > 0)
            {
                return new PacketDecision(
                    packet.Header.Identification,
                    Verdict.Verdict.DROP,
                    $"Token bucket exceeded: {string.Join(", ", exceededRules)}",
                    RuleName);
            }

            return NoMatch(packet, "Token bucket limit not exceeded");
        }


        private bool TryConsumeToken(
            RateLimitKey key,
            TokenBucketOptions options,
            DateTimeOffset now)
        {
            var state = _bucketStorage.GetOrAdd(
                key,
                _ => new TokenBucketState
                {
                    Tokens = options.Capacity,
                    LastRefill = now
                });

            lock (state.SyncRoot)
            {
                
                var elapsedSeconds =
                    Math.Max(0, (now - state.LastRefill).TotalSeconds);

                
                state.Tokens = Math.Min(
                    options.Capacity,
                    state.Tokens +
                    elapsedSeconds * options.TokenPerSeconds);

                state.LastRefill = now;

             
                if (state.Tokens < options.TokenPerPacket)
                {
                    return false;
                }

              
                state.Tokens -= options.TokenPerPacket;

                return true;
            }
        }



        private PacketDecision NoMatch(
            IPv4Packet packet,
            string reason)
        {
            return new PacketDecision(
                packet.Header.Identification,
                Verdict.Verdict.NO_MATCH,
                reason,
                RuleName);
        }
    }
}