
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

using Avalonia.Controls;
using MFirewallApp.Analyse;
using MFirewallApp.Rules.StatefulRule;

namespace MFirewallAppUI
{
    public partial class ConnectionTable : Window
    {
        private readonly Dictionary<ConnectionKey, ConnectionSnapshot> _existing = new();
        public ObservableCollection<ConnectionSnapshot> Connections { get; } = new();

        public ConnectionTable()
        {
            InitializeComponent();
            DataContext = this;
            Connections.Clear();
         
           
        }   

        public void AddConnection(ConnectionSnapshot snapshot)
        {
            if (_existing.TryGetValue(snapshot.ConnectionKey, out var connSnapshot))
            {
                if (snapshot.ConnectionState != connSnapshot.ConnectionState)
                {
                    Console.WriteLine(
                    $"SRC={snapshot.ConnectionKey.SourcePort}, DST={snapshot.ConnectionKey.DestinationPort}");
                    _existing[snapshot.ConnectionKey] = snapshot;
                    var index = Connections.IndexOf(connSnapshot);
                    if (index >= 0)
                    {
                        Connections[index] = snapshot;
                    }
                    else
                    {
                        Connections.Add(snapshot);
                    }
                }
                return;
            }
            _existing[snapshot.ConnectionKey] = snapshot;
            Connections.Add(snapshot);
        }
    }
}