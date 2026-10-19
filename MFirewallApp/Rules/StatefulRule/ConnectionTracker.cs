using System.Collections.Concurrent;
using System.Text;
using Domain.Models.Packets;
using MFirewallApp.Analyse;
using MFirewallApp.FileSystem;
using MFirewallApp.Interface;
using MFirewallApp.Service;
using MFirewallApp.Verdict;
namespace MFirewallApp.Rules.StatefulRule
{
    public class ConnectionTracker : IConnectionTracker
    {
        private readonly ConcurrentDictionary<ConnectionKey, ConnectionState> _connectionTables = new();

        private readonly object _locker = new();

        private readonly ConnectionQueue conQueue;

        private readonly ReportQueue repQueue;

        public ConnectionTracker(ConnectionQueue connectionQueue, ReportQueue reportQueue)
        {
            conQueue = connectionQueue;
            repQueue = reportQueue;
        }

        public async Task<PacketDecision> ProcessConnectionAsync(IPv4Packet packet)
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
            
            
            if (tcp.Header.IsRst)
            {
                lock (_locker)
                {
                    _connectionTables.TryRemove(connectionKey, out _);
                    _connectionTables.TryRemove(reversedKey, out _);
                }

                
                var decision = new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "Tcp connection reset", "Stateful rule");
               

                return decision;
               
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
                ConnectionState connectionState;
                if (_connectionTables.ContainsKey(connectionKey))
                {
                    connectionState = _connectionTables[connectionKey];
                    conQueue.Equeue(new ConnectionSnapshot(connectionKey, connectionState));
                }
                if (_connectionTables.ContainsKey(reversedKey))
                {
                    connectionState = _connectionTables[reversedKey];
                    conQueue.Equeue(new ConnectionSnapshot(reversedKey, connectionState));
                }
                

                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.ACCEPT, "Tracked connection", "Stateful rule");
            }
            if (isNewSyn)
            {
                return new PacketDecision(packet.Header.Identification, Verdict.Verdict.NO_MATCH, "New connection", "Stateful rule");
            }
            var dropDecision = new PacketDecision(packet.Header.Identification, Verdict.Verdict.DROP, "Unknown connection", "Stateful rule");
            
            repQueue.Equeue(new FirewallReport(DateTimeOffset.UtcNow,dropDecision));
            return dropDecision;
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
           
            var sb = new StringBuilder();
            ResetTable();
            
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