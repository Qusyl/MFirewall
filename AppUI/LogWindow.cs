using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;

namespace MFirewallAppUI
{
    public partial class LogWindow : Window
    {
        public LogWindow()
        {
            InitializeComponent();
            
        }
        public void AddLog(string message)
        {
            var time = DateTimeOffset.UtcNow.ToString("HH:mm:ss");

            LogsList.Items.Add($"[{time}] {message}");
        }
         public void ClearLogs()
        {
            LogsList.Items.Clear();
        }
    }
}