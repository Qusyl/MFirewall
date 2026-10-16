
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

using Domain.Models.Packets;
using Domain.Values;
using MFirewallApp.Interface;
using MFirewallApp.Rules.FloodRule.Detectors.Flood;
using MFirewallApp.Rules.PortScanRule.Options;


namespace MFirewallApp.Rules.RateLimitRule
{
    public class RateLimitRule : IPacketRule
    {
        public string RuleName => "rate_limit_rule";

        public int RuleScore => 100;

        private readonly ConcurrentDictionary<RateLimitKey, FixedWindowState> _windowStorage = new();

        private readonly ConcurrentDictionary<RateLimitKey, TokenBucketState> _bucketStorage = new();

        public Verdict.Verdict Check(IPv4Packet packet, FirewallProtection configuration)
        {
            var options = configuration.RateLimitOptions;

            if (options.Algorithm is RateLimitAlgorithm.FIXED_WINDOW)
            {
                return FixedWindow(packet, options);
            }

            return TokenBucket(packet, options);
        }
        private Verdict.Verdict TokenBucket(IPv4Packet packet, RateLimitOptions options)
        {
            var currentIp = packet.Header.SourceAddress;
            var transportPacket = packet.ExtractPacket();
            var currentTime = DateTimeOffset.UtcNow;
            var protocol = packet.Header.Protocol;
            ushort port = transportPacket switch
            {
                UdpPacket udp => udp.Header.DestinationPort,
                TcpPacket tcp => tcp.Header.DestinationPort,
                _ => ushort.MaxValue
            };

            
            if (options.Ip.Enable)
            {
                var key = new RateLimitKey(RateLimitScope.IP, currentIp.ToString());
                var state = _bucketStorage.GetOrAdd(key, _ => new TokenBucketState
                {
                    Tokens = options.TokenBucket.Capacity,
                    LastRefill = currentTime
                });

                lock (state.SyncRoot)
                {
                    var elapsedSeconds = (currentTime - state.LastRefill).TotalSeconds;

                    state.Tokens = Math.Min(
                      options.TokenBucket.Capacity,
                     state.Tokens +
                     elapsedSeconds * options.TokenBucket.TokenPerSeconds);

                    state.LastRefill = currentTime;

                    if (state.Tokens < 1)
                    {
                        return Verdict.Verdict.DROP;
                    }
                    state.Tokens -= options.TokenBucket.TokenPerPacket;
                }
                
            }
            if (options.Port.Enable && port != ushort.MaxValue)
            {
                var key = new RateLimitKey(RateLimitScope.PORT, port.ToString());
                var state = _bucketStorage.GetOrAdd(key, _ => new TokenBucketState
                {
                    Tokens = options.TokenBucket.Capacity,
                    LastRefill = currentTime
                });

                lock (state.SyncRoot)
                {
                    var elapsedSeconds = (currentTime - state.LastRefill).TotalSeconds;

                    state.Tokens = Math.Min(
                      options.TokenBucket.Capacity,
                     state.Tokens +
                     elapsedSeconds * options.TokenBucket.TokenPerSeconds);

                    state.LastRefill = currentTime;

                    if (state.Tokens < 1)
                    {
                        return Verdict.Verdict.DROP;
                    }
                    state.Tokens -= options.TokenBucket.TokenPerPacket;
                }
            }
            if (options.Protocol.Enable)
            {
                var key = new RateLimitKey(RateLimitScope.PROTOCOL, protocol.ToString());
                var state = _bucketStorage.GetOrAdd(key, _ => new TokenBucketState
                {
                    Tokens = options.TokenBucket.Capacity,
                    LastRefill = currentTime
                });

                lock (state.SyncRoot)
                {
                    var elapsedSeconds = (currentTime - state.LastRefill).TotalSeconds;

                    state.Tokens = Math.Min(
                      options.TokenBucket.Capacity,
                     state.Tokens +
                     elapsedSeconds * options.TokenBucket.TokenPerSeconds);

                    state.LastRefill = currentTime;

                    if (state.Tokens < 1)
                    {
                        return Verdict.Verdict.DROP;
                    }
                    state.Tokens -= options.TokenBucket.TokenPerPacket;
                }
              
            }
            return Verdict.Verdict.ACCEPT;
        }

        private Verdict.Verdict FixedWindow(IPv4Packet packet, RateLimitOptions options)
        {
            var currentIp = packet.Header.SourceAddress;
            var transportPacket = packet.ExtractPacket();
            var currentTime = DateTimeOffset.UtcNow;
            var protocol = packet.Header.Protocol;
            ushort port = transportPacket switch
            {
                UdpPacket udp => udp.Header.DestinationPort,
                TcpPacket tcp => tcp.Header.DestinationPort,
                _ => ushort.MaxValue
            };

            if (options.Ip.Enable)
            {
                var ipKey = new RateLimitKey(RateLimitScope.IP, currentIp.ToString());
                var state = _windowStorage.GetOrAdd(ipKey, _ => new FixedWindowState
                {
                    WindowStart = currentTime,
                    PacketCount = 1
                });

                lock (state.syncRoot)
                {
                    if (state.WindowStart + TimeSpan.FromSeconds(options.Ip.WindowSeconds) < currentTime)
                    {
                        state = new FixedWindowState
                        {
                            WindowStart = currentTime,
                            PacketCount = 0
                        };
                    }

                    state.PacketCount++;

                    if(state.PacketCount > options.Ip.MaxPackets)
                    {
                         return Verdict.Verdict.DROP;
                    }
                }
            }

            if (options.Port.Enable)
            {
                var portKey = new RateLimitKey(RateLimitScope.PORT, port.ToString());
                var state = _windowStorage.GetOrAdd(portKey, _ => new FixedWindowState
                {
                    WindowStart = currentTime,
                    PacketCount = 1
                });

                lock (state.syncRoot)
                {
                    if (state.WindowStart + TimeSpan.FromSeconds(options.Port.WindowSeconds) < currentTime)
                    {
                        state = new FixedWindowState
                        {
                            WindowStart = currentTime,
                            PacketCount = 0
                        };
                    }

                    state.PacketCount++;

                    if(state.PacketCount > options.Port.MaxPackets)
                    {
                         return Verdict.Verdict.DROP;
                    }
                }
            }
            if (options.Protocol.Enable)
            {
                var protocolKey = new RateLimitKey(RateLimitScope.PROTOCOL, protocol.ToString());
                var state = _windowStorage.GetOrAdd(protocolKey, _ => new FixedWindowState
                {
                    WindowStart = currentTime,
                    PacketCount = 1
                });

                lock (state.syncRoot)
                {
                    if (state.WindowStart + TimeSpan.FromSeconds(options.Protocol.WindowSeconds) < currentTime)
                    {
                        state = new FixedWindowState
                        {
                            WindowStart = currentTime,
                            PacketCount = 0
                        };
                    }

                    state.PacketCount++;

                    if(state.PacketCount > options.Protocol.MaxPackets)
                    {
                         return Verdict.Verdict.DROP;
                    }
                }
            }
            return Verdict.Verdict.ACCEPT;
        }
    }
}

