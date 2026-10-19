using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using MFirewallApp.Hubs;
using MFirewallApp.Analyse;
using MFirewallApp.Rules;
using Microsoft.AspNetCore.SignalR.Client;
using MFirewallApp.FileSystem;

namespace MFirewallAppUI;

public partial class MainWindow : Window
{
    private LogWindow? logWindow;

    private readonly HubConnection _loggerConnection;

    private const string ConfigPath =
        "/home/denis/Documents/Kursovie/Security/Api/MFirewallApi/configuration/firewall_configuration.json";

    private sealed class ConfigFileRoot
{
    public FirewallConfiguration FirewallConfiguration { get; set; } = new();
}
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private FirewallConfiguration _config = new();

    public MainWindow()
    {
        InitializeComponent();
        LoadConfig();
        _loggerConnection = new HubConnectionBuilder()
        .WithUrl("http://localhost:5118/logger")
        .WithAutomaticReconnect()
        .Build();
        _loggerConnection.Reconnecting += error =>
        {
            FileLogger.AppendLogFile($"[SignalR] Переподключение: {error?.Message}");

            return Task.CompletedTask;
        };
        _loggerConnection.Reconnected += connectionId =>
        {FileLogger.AppendLogFile($"[SignalR] Переподключились: {connectionId}");
          
            return Task.CompletedTask;
        };
        _loggerConnection.Closed += error =>
        {
            FileLogger.AppendLogFile($"[SignalR] Соединение закрыто: {error?.Message}");
         
            return Task.CompletedTask;
        };
        _loggerConnection.On<FirewallReport>("GetReport", (report) =>
        {
            var reason = report.PacketDecision.Reason ?? "не указано";
            var rule = report.PacketDecision.MatchedRule ?? "не указано";
            var verdict = report.PacketDecision.Verdict;
            var id = report.PacketDecision.PacketQueueId;
            var log = $"[{report.Identified.ToString("HH-mm-ss")}] "
            + $"пакет[{id}] "
            + $"правило {rule} "
            + $"вердикт {verdict}"
            + $"причина {reason}"
            ;
            FileLogger.AppendLogFile("ПОЛУЧЕН ЛОГ ОТ СИГНАЛ! " + log);
            Dispatcher.Post(() =>
            {
                LoadLogWindow();
                {
                    logWindow?.AddLog(log);
                }  
            });
        });
        _ = ConnectWithRetryAsync(_loggerConnection);       
       
    }

    private static async Task  ConnectWithRetryAsync(HubConnection connection)
    {
        while (true)
        {
            try
            {
                await connection.StartAsync();
                FileLogger.AppendLogFile($"[SignalR] Успешно подключились к Logger Hub");
              
                break;
            }
            catch(Exception ex)
            {
                FileLogger.AppendLogFile($"[SignalR] Ошибка подключения к Logger Hub {ex?.Message}");
                await Task.Delay(5000);
            }
        }
    }
    private void LoadLogWindow()
    {
         if (logWindow is null)
        {
            logWindow = new LogWindow();
            
            logWindow.Closed += (_, _) =>
            {
                logWindow.ClearLogs();
                logWindow = null;
            };
        }
    }
    private void OnLoadClick(object? sender, RoutedEventArgs e) => LoadConfig();

    private void OnSaveClick(object? sender, RoutedEventArgs e) => SaveConfig();

    private void LoadConfig()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                
                var json = File.ReadAllText(ConfigPath);
                using var doc = JsonDocument.Parse(json);
                var node = doc.RootElement.TryGetProperty("FirewallConfiguration", out var section) ? section : doc.RootElement;
                _config = node.Deserialize<FirewallConfiguration>(JsonOptions) ?? new FirewallConfiguration();
                StatusText.Text = "Загружено: " + ConfigPath;
            }
            else
            {
                _config = new FirewallConfiguration();
                StatusText.Text = "Файла нет, показаны значения по умолчанию";
            }
        }
        catch (Exception ex)
        {
            _config = new FirewallConfiguration();
            StatusText.Text = "Ошибка чтения: " + ex.Message;
        }

        FillEnumLists();      
        DataContext = _config; 
    }

   
    private void FillEnumLists()
    {
        RuleStrategyBox.ItemsSource = EnumValues(_config.RuleStrategy);
        ProtocolBox.ItemsSource = EnumValues(_config.FirewallProtection.ProtocolOptions.Protocol);
        AlgorithmBox.ItemsSource = EnumValues(_config.FirewallProtection.RateLimitOptions.Algorithm);
    }

    private static Array? EnumValues(object? value)
    {
        if (value is null) return null;
        var type = value.GetType();
        return type.IsEnum ? Enum.GetValues(type) : null;
    }

    private void OnLogWindow_Click(object? sender, RoutedEventArgs eventArgs)
    {
        LoadLogWindow();

        if (!logWindow!.IsVisible)
        {
            logWindow.Show(this);
        }
        else
        {
            logWindow.Activate();
        }

    }

    private void SaveConfig()
    {
        try
        {
           
            Focus();

            
            var json = JsonSerializer.Serialize(
                new ConfigFileRoot { FirewallConfiguration = _config }, JsonOptions);

            var dir = Path.GetDirectoryName(ConfigPath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var tmp = ConfigPath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, ConfigPath, overwrite: true);

            StatusText.Text = "Сохранено " + DateTime.Now.ToString("HH:mm:ss");
        }
        catch (Exception ex)
        {
            StatusText.Text = "Ошибка записи: " + ex.Message;
        }
    }
}