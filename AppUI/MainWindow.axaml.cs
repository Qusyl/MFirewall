using System;
using System.IO;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;
using MFirewallApp.Rules;

namespace MFirewallAppUI;

public partial class MainWindow : Window
{
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