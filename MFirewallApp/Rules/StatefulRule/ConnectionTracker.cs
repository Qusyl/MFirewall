using System.Collections.Concurrent;
using System.Text;
using Domain.Models.Packets;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Verdict;
namespace MFirewallApp.Rules.StatefulRule
{
    public class ConnectionTracker : IConnectionTracker
    {
        private readonly ConcurrentDictionary<ConnectionKey, ConnectionState> _connectionTables = new();

        private readonly object _locker = new();

        public PacketDecision ProcessConnection(IPv4Packet packet)
        {
            if (packet.ExtractPacket() is not TcpPacket tcp)
            {
                var verdictNoTcp = new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Not TCP", "Stateful rule");

                return verdictNoTcp;
            }
            
            var connectionKey = new ConnectionKey(
            packet.Header.SourceAddress.ToString(),
            tcp.Header.SourcePort,
            packet.Header.DestinationAddress.ToString(),
            tcp.Header.DestinationPort,
            Domain.Values.Protocol.TCP);

            var reversedKey = connectionKey.Reverse();
            var hasDirect = _connectionTables.TryGetValue(
    connectionKey,
    out var directState);

var hasReverse = _connectionTables.TryGetValue(
    reversedKey,
    out var reverseState);

            Console.WriteLine(
    $"[CONNECTION LOOKUP] " +
    $"Src={connectionKey.SourceIp}:{connectionKey.SourcePort}, " +
    $"Dst={connectionKey.DestionationIp}:{connectionKey.DestinationPort}, " +
    $"SYN={tcp.Header.IsSyn}, " +
    $"ACK={tcp.Header.IsAck}, " +
    $"FIN={tcp.Header.IsFin}, " +
    $"RST={tcp.Header.IsRst}, " +
    $"Direct={hasDirect} ({directState?.Status}), " +
    $"Reverse={hasReverse} ({reverseState?.Status})");
    Console.WriteLine(
    $"[TCP FLAGS] " +
    $"{packet.Header.SourceAddress}:{tcp.Header.SourcePort} -> " +
    $"{packet.Header.DestinationAddress}:{tcp.Header.DestinationPort} | " +
    $"SYN={tcp.Header.IsSyn}, " +
    $"ACK={tcp.Header.IsAck}, " +
    $"FIN={tcp.Header.IsFin}, " +
    $"RST={tcp.Header.IsRst}");

            if (tcp.Header.IsRst)
            {
                lock (_locker)
                {
                    _connectionTables.TryRemove(connectionKey, out _);
                    _connectionTables.TryRemove(reversedKey, out _);
                }

                SaveConnectionTable();

                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Tcp connection reset", "Stateful rule");
               
            }

            var now = DateTimeOffset.UtcNow;

            lock (_locker)
            {
                if (tcp.Header.IsFin)
                {
                    ProcessFin(connectionKey, reversedKey, tcp, now);
                }

                if (tcp.Header.IsSyn && !tcp.Header.IsAck)
                {
                    _connectionTables.TryAdd(
                        connectionKey,
                        new ConnectionState
                        {
                            Status = TcpConnectionStatus.SynSent,
                            LastActive = now
                        });
                }

                else if (tcp.Header.IsSyn && tcp.Header.IsAck)
                {
                    Console.WriteLine(
        $"[SYN-ACK] " +
        $"{connectionKey.SourceIp}:{connectionKey.SourcePort} -> " +
        $"{connectionKey.DestionationIp}:{connectionKey.DestinationPort}");

                    Console.WriteLine(
                        $"[SYN-ACK LOOKUP] Reverse={reversedKey.SourceIp}:" +
                        $"{reversedKey.SourcePort} -> " +
                        $"{reversedKey.DestionationIp}:{reversedKey.DestinationPort}");
                    if (_connectionTables.TryGetValue(
                            reversedKey, out var state) &&
                        state.Status == TcpConnectionStatus.SynSent)
                    {
                        state.Status = TcpConnectionStatus.SynReceived;
                        state.LastActive = now;
                    }
                }

                else if (!tcp.Header.IsSyn && tcp.Header.IsAck && !tcp.Header.IsFin && !tcp.Header.IsRst)
                {
                    if (_connectionTables.TryGetValue(
                            connectionKey, out var state) &&
                        state.Status == TcpConnectionStatus.SynReceived)
                    {
                        state.Status = TcpConnectionStatus.Established;
                        state.LastActive = now;
                    }
                }
            }
            bool known;
            lock (_locker)
            {
                known = _connectionTables.ContainsKey(connectionKey) || _connectionTables.ContainsKey(reversedKey);
            }
            SaveConnectionTable();

            var isNewSyn = tcp.Header.IsSyn && !tcp.Header.IsAck;
            if (known)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "Tracked connection", "Stateful rule");
            }
            if (isNewSyn)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "New connection",     "Stateful rule");
            }
            return new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, "Unknown connection",     "Stateful rule");
        }

        public int CleanupExpiredConnections(TimeSpan timeout)
        {
            var now = DateTimeOffset.UtcNow;

            var removed = 0;

            lock (_locker)
            {
                foreach (var entry in _connectionTables.ToArray())
                {
                    var key = entry.Key;

                    var state = entry.Value;

                    if (now - state.LastActive < timeout)
                    {
                        continue;
                    }

                    if (_connectionTables.TryRemove(key, out _))
                    {
                        removed++;
                    }
                }
            }
            return removed;
        }

        private void ResetTable()
        {
            var path = "/home/denis/Documents/Kursovie/Security/MFirewallApp/FileSystem/connection_table.txt";
            File.WriteAllText(path, "");
        }
        private void SaveConnectionTable()
        {

            var path = "/home/denis/Documents/Kursovie/Security/MFirewallApp/FileSystem/connection_table.txt";
            Console.WriteLine(
    $"[SAVE TABLE] Entries={_connectionTables.Count}, " +
    $"Path={path}");
            var sb = new StringBuilder();
            ResetTable();
            foreach (var (connectionKey, state) in _connectionTables)
            {
                 Console.WriteLine(
        $"[TABLE] {connectionKey.SourceIp}:{connectionKey.SourcePort} -> " +
        $"{connectionKey.DestionationIp}:{connectionKey.DestinationPort}, " +
        $"Status={state.Status}");
                sb.Append("--------------------------------------" + Environment.NewLine);
                sb.Append($"|{connectionKey.SourceIp}:{connectionKey.SourcePort} --> {connectionKey.DestionationIp}:{connectionKey.DestinationPort}|\n");
                sb.Append($"STATUS: {state.Status.ToString()}|\n");
                sb.Append($"CREATED_AT: {state.CreatedAt.ToString("dd-MM-yyyy HH:mm:ss")}|\n");
                sb.Append($"LAST_ACTIVE: {state.LastActive.ToString("dd-MM-yyyy HH:mm:ss")}|\n");
                sb.Append($"CLIENT_FIN: {state.ClientFinSeen}|\n");
                sb.Append($"SERVER_FIN: {state.ServerFinSeen}|\n");
                sb.Append("--------------------------------------" + Environment.NewLine);
            }
            File.WriteAllText(path, sb.ToString());
        }

        private void ProcessFin(
                ConnectionKey connectionKey,
                ConnectionKey reversedKey,
                TcpPacket tcp,
                DateTimeOffset now
        )
        {
            ConnectionKey storedKey;

            ConnectionState state;

            if (_connectionTables.TryGetValue(connectionKey, out state!))
            {
                storedKey = connectionKey;
                state.ClientFinSeen = true;
            }
            else if (_connectionTables.TryGetValue(reversedKey, out state!))
            {
                storedKey = reversedKey;
                state.ServerFinSeen = true;
            }
            else
            {
                return;
            }

            state.Status = TcpConnectionStatus.Closing;
            state.LastActive = now;

            if(state.ClientFinSeen && state.ServerFinSeen)
            {
                _connectionTables.TryRemove(storedKey, out _);
            }
        }

    }
        
    }   