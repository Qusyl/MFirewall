using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using MFirewallApp.Analyse;

namespace MFirewallAppUI
{
    public partial class LogWindow : Window
    {
        public ObservableCollection<FirewallReport> Logs { get; } = new();
        public LogWindow()
        {
            InitializeComponent();
            DataContext = this;
            Logs.Add(new FirewallReport(DateTimeOffset.UtcNow, new MFirewallApp.Verdict.PacketDecision(0,MFirewallApp.Verdict.Verdict.NO_MATCH,"Test","Test")));
            
        }
        public void AddLog(FirewallReport report)
        {
            Logs.Add(report);
        }
        public void ClearLogs()
        {
           
        }
        private void OnClear_Log(object sender, RoutedEventArgs args)
        {
            ClearLogs();
        }
    }
}