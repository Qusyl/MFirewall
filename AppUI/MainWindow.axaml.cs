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
using MFirewallApp.Rules.StatefulRule;

namespace MFirewallAppUI;

public partial class MainWindow : Window
{
    private LogWindow? logWindow;
    private ConnectionTable? connectionTable;
    private HttpWindow? _httpProxyWindow;
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

    

    private bool _isAdmin = false;
    public bool IsAdmin
    {
        get => _isAdmin;
        set
        {
            if (_isAdmin == value) return;
            _isAdmin = value;
            UpdateVisualState();
        }
    }

    private bool _isAuthorized = false;
    public bool IsAuthorized
    {
        get => _isAuthorized;
        set
        {
            if (_isAuthorized == value) return;
            _isAuthorized = value;
            UpdateVisualState();
        }
    }

    private FirewallConfiguration _config = new();

    public MainWindow()
    {
        InitializeComponent();
        Opened += (_, _) => UpdateVisualState();
        LoadConfig();

        _loggerConnection = new HubConnectionBuilder()
            .WithUrl("http://localhost:5120/logger")
            .WithAutomaticReconnect()
            .Build();

        _loggerConnection.Reconnecting += error =>
        {
            FileLogger.AppendLogFile($"[SignalR] Переподключение: {error?.Message}");
            return Task.CompletedTask;
        };
        _loggerConnection.Reconnected += connectionId =>
        {
            FileLogger.AppendLogFile($"[SignalR] Переподключились: {connectionId}");
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
                    + $"вердикт {verdict} "
                    + $"причина {reason}";
            FileLogger.AppendLogFile("ПОЛУЧЕН ЛОГ ОТ СИГНАЛ! " + log);

            Dispatcher.Post(() =>
            {
                LoadLogWindow();
                logWindow?.AddLog(report);
            });
        });

        _loggerConnection.On<ConnectionSnapshot>("GetConnections", (snapshot) =>
        {
            Dispatcher.Post(() =>
            {
                LoadConnectionWindow();
                connectionTable?.AddConnection(snapshot);
            });
        });

        _ = ConnectWithRetryAsync(_loggerConnection);
    }

    private void UpdateVisualState()
    {
        // Защита: если вдруг вызовут до InitializeComponent (например, из будущего кода)
        if (AuthOverlay is null || ContentRoot is null || RoleBadge is null || RoleText is null)
            return;

        AuthOverlay.IsVisible = !IsAuthorized;

        // Только админ может редактировать контент
        ContentRoot.IsEnabled = IsAuthorized && IsAdmin;

        RoleBadge.Classes.Set("admin", IsAuthorized && IsAdmin);
        RoleBadge.Classes.Set("user", !IsAuthorized || !IsAdmin);

        RoleText.Text = !IsAuthorized ? "Гость"
                      : IsAdmin       ? "Администратор"
                                      : "Пользователь";
    }

    private void OnLoginAgainClick(object? sender, RoutedEventArgs e)
    {
        var auth = new AuthorizationWindow();
        auth.Closed += (_, _) =>
        {
            if (!auth.IsAuthorized) return;
            IsAuthorized = true;
            IsAdmin = auth.IsAdmin;
        };
        auth.ShowDialog(this);
    }

    private void OnHttpProxy_Click(object? sender, RoutedEventArgs e)
    {
        if (_httpProxyWindow is null)
        {
            _httpProxyWindow = new HttpWindow();
            _httpProxyWindow.Closed += (_, _) => _httpProxyWindow = null;
        }

        if (!_httpProxyWindow.IsVisible)
            _httpProxyWindow.Show(this);
        else
            _httpProxyWindow.Activate();
    }

    private static async Task ConnectWithRetryAsync(HubConnection connection)
    {
        while (true)
        {
            try
            {
                await connection.StartAsync();
                FileLogger.AppendLogFile("[SignalR] Успешно подключились к Logger Hub");
                break;
            }
            catch (Exception ex)
            {
                FileLogger.AppendLogFile($"[SignalR] Ошибка подключения к Logger Hub {ex.Message}");
                await Task.Delay(5000);
            }
        }
    }

    private void OnAddDestinationIp(object? sender, RoutedEventArgs args)
    {
        var subnetIp = NewDestinationIpBox.Text?.Trim();
        var subnetMask = NewDestinationMaskBox.Text?.Trim();
        var subnet = $"{subnetIp}/{subnetMask}";
        if (!string.IsNullOrEmpty(subnet) && !_config.FirewallProtection.DestinationIpOptions.DestinationAddress.Contains(subnet))
        {
            _config.FirewallProtection.DestinationIpOptions.DestinationAddress.Add(subnet);
            RefreshAllLists();
            NewDestinationIpBox.Text = string.Empty;
            NewDestinationMaskBox.Text = string.Empty;
        }
    }
    private void OnAddSourceIp(object? sender, RoutedEventArgs args)
    {
        var subnetIp = NewSourceIpBox.Text?.Trim();
        var subnetMask = NewSourceMaskBox.Text?.Trim();
        var subnet = $"{subnetIp}/{subnetMask}";
        if (!string.IsNullOrEmpty(subnet) && !_config.FirewallProtection.SourceIpOptions.SourceAddress.Contains(subnet))
        {
            _config.FirewallProtection.SourceIpOptions.SourceAddress.Add(subnet);
            RefreshAllLists();
            NewDestinationIpBox.Text = string.Empty;
            NewDestinationMaskBox.Text = string.Empty;
        }
    }

    private void OnRemoveSourceIp(object? sender, RoutedEventArgs args)
    {
         if(SourceIpList.SelectedItem is string subnet)
            {
                _config.FirewallProtection.SourceIpOptions.SourceAddress.Remove(subnet);
                RefreshAllLists();
            }
    }
    private void RefreshAllLists()
    {
        SourceIpList.ItemsSource = _config.FirewallProtection.SourceIpOptions.SourceAddress;
        DestinationIpList.ItemsSource = _config.FirewallProtection.DestinationIpOptions.DestinationAddress;
    }
    private void OnRemoveDestinationIp(object? sender, RoutedEventArgs args)
    {
        if(DestinationIpList.SelectedItem is string subnet)
            {
                _config.FirewallProtection.DestinationIpOptions.DestinationAddress.Remove(subnet);
                RefreshAllLists();
            }
    }

    private void LoadConnectionWindow()
    {
        if (connectionTable is null)
        {
            connectionTable = new ConnectionTable();
            connectionTable.Closed += (_, _) => connectionTable = null;
        }
    }

    private void LoadLogWindow()
    {
        if (logWindow is null)
        {
            logWindow = new LogWindow();
            logWindow.Closed += (_, _) => logWindow = null;
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
                var node = doc.RootElement.TryGetProperty("FirewallConfiguration", out var section)
                    ? section
                    : doc.RootElement;
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
        RefreshAllLists();
        DataContext = _config;
    }

    private void FillEnumLists()
    {
        RuleStrategyBox.ItemsSource = EnumValues(_config.RuleStrategy);
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
            logWindow.Show(this);
        else
            logWindow.Activate();
    }

    private void OnConnectionTable_Click(object? sender, RoutedEventArgs eventArgs)
    {
        LoadConnectionWindow();

        if (!connectionTable!.IsVisible)
            connectionTable.Show(this);
        else
            connectionTable.Activate();
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