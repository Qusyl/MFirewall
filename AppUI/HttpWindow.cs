

using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Interactivity;
using MFirewallApp.Rules;
using MFirewallAppUI.Models;

namespace MFirewallAppUI
{
    public partial class HttpWindow : Window
    {
        private const string ConfigPath =
        "/home/denis/Documents/Kursovie/Security/Api/MFirewallApi/configuration/http_proxy_configuration.json";

        private ObservableCollection<SubnetEntry> _subnets = new();

        

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private sealed class ConfigFileRoot
    {
        public HttpProxyConfiguration HttpProxyConfiguration { get; set; } = new();
    }

    private HttpProxyConfiguration _config = new();

    public HttpWindow()
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

              
                var node = FindHttpProxySection(doc.RootElement);

                _config = node?.Deserialize<HttpProxyConfiguration>(JsonOptions)
                          ?? new HttpProxyConfiguration();

                StatusText.Text = "Загружено: " + ConfigPath;
            }
            else
            {
                _config = new HttpProxyConfiguration();
                StatusText.Text = "Файла нет, показаны значения по умолчанию";
            }
        }
        catch (Exception ex)
        {
            _config = new HttpProxyConfiguration();
            StatusText.Text = "Ошибка чтения: " + ex.Message;
        }

        RefreshAllLists();
    }

    private void SaveConfig()
    {
        try
        {
            Focus(); 

          
            ConfigFileRoot? root = null;

            if (File.Exists(ConfigPath))
            {
                var existingJson = File.ReadAllText(ConfigPath);
                using var doc = JsonDocument.Parse(existingJson);
                root = doc.RootElement.Deserialize<ConfigFileRoot>(JsonOptions)
                       ?? new ConfigFileRoot();
            }

            root ??= new ConfigFileRoot();
            root.HttpProxyConfiguration = _config;

            var json = JsonSerializer.Serialize(root, JsonOptions);

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

    private static JsonElement? FindHttpProxySection(JsonElement root)
    {
        if (root.TryGetProperty("HttpProxyConfiguration", out var section))
            return section;

       
        if (root.TryGetProperty("AllowedDomainOptions", out _))
            return root;

        return null;
    }



    private void RefreshAllLists()
    {
        AllowedDomainsList.ItemsSource = _config.AllowedDomainOptions.AllowedDomains;
        BlackListDomainsList.ItemsSource = _config.BlackListDomainOptions.BlackList;
        QueryParamsList.ItemsSource = _config.UrlOptions.NotAllowedQueryParameters;
        KeywordsList.ItemsSource = _config.UrlOptions.NotAllowedKeyWords;
        ExtensionsList.ItemsSource = _config.UrlOptions.BlockedExtensions;
            PortsList.ItemsSource = _config.HttpsOptions.AllowedPorts;
            SubnetsList.ItemsSource = _config.SubnetOptions.BlockedCidrList;
    }

    private void OnAddSubnet(object? sender, RoutedEventArgs e)
    {
            var subnetIp = NewSubnetIpBox.Text?.Trim();
            var subnetMask = NewSubnetMaskBox.Text?.Trim();
            var subnet = $"{subnetIp}/{subnetMask}";
            if (!string.IsNullOrEmpty(subnet) && !_config.SubnetOptions.BlockedCidrList.Contains(subnet))
            {
                _config.SubnetOptions.BlockedCidrList.Add(subnet);
                RefreshAllLists();
                NewSubnetIpBox.Text = string.Empty;
                NewSubnetMaskBox.Text = string.Empty;
            }
    }
    private void OnAddAllowedDomain(object? sender, RoutedEventArgs e)
    {
        var v = NewAllowedDomainBox.Text?.Trim();
        if (!string.IsNullOrEmpty(v) && !_config.AllowedDomainOptions.AllowedDomains.Contains(v))
        {
            _config.AllowedDomainOptions.AllowedDomains.Add(v);
            RefreshAllLists();
            NewAllowedDomainBox.Text = string.Empty;
        }
    }

    private void OnRemoveAllowedDomain(object? sender, RoutedEventArgs e)
    {
        if (AllowedDomainsList.SelectedItem is string s)
        {
            _config.AllowedDomainOptions.AllowedDomains.Remove(s);
            RefreshAllLists();
        }
    }


    private void OnAddBlackDomain(object? sender, RoutedEventArgs e)
    {
        var v = NewBlackDomainBox.Text?.Trim();
        if (!string.IsNullOrEmpty(v) && !_config.BlackListDomainOptions.BlackList.Contains(v))
        {
            _config.BlackListDomainOptions.BlackList.Add(v);
            RefreshAllLists();
            NewBlackDomainBox.Text = string.Empty;
        }
    }

    private void OnRemoveBlackDomain(object? sender, RoutedEventArgs e)
    {
        if (BlackListDomainsList.SelectedItem is string s)
        {
            _config.BlackListDomainOptions.BlackList.Remove(s);
            RefreshAllLists();
        }
    }

    
    private void OnAddQueryParam(object? sender, RoutedEventArgs e)
    {
        var v = NewQueryParamBox.Text?.Trim();
        if (!string.IsNullOrEmpty(v) && !_config.UrlOptions.NotAllowedQueryParameters.Contains(v))
        {
            _config.UrlOptions.NotAllowedQueryParameters.Add(v);
            RefreshAllLists();
            NewQueryParamBox.Text = string.Empty;
        }
    }

    private void OnRemoveQueryParam(object? sender, RoutedEventArgs e)
    {
        if (QueryParamsList.SelectedItem is string s)
        {
            _config.UrlOptions.NotAllowedQueryParameters.Remove(s);
            RefreshAllLists();
        }
    }

  
    private void OnAddKeyword(object? sender, RoutedEventArgs e)
    {
        var v = NewKeywordBox.Text?.Trim();
        if (!string.IsNullOrEmpty(v) && !_config.UrlOptions.NotAllowedKeyWords.Contains(v))
        {
            _config.UrlOptions.NotAllowedKeyWords.Add(v);
            RefreshAllLists();
            NewKeywordBox.Text = string.Empty;
        }
    }

    private void OnRemoveKeyword(object? sender, RoutedEventArgs e)
    {
        if (KeywordsList.SelectedItem is string s)
        {
            _config.UrlOptions.NotAllowedKeyWords.Remove(s);
            RefreshAllLists();
        }
    }

   
    private void OnAddExtension(object? sender, RoutedEventArgs e)
    {
        var v = NewExtensionBox.Text?.Trim();
        if (!string.IsNullOrEmpty(v) && !_config.UrlOptions.BlockedExtensions.Contains(v))
        {
            _config.UrlOptions.BlockedExtensions.Add(v);
            RefreshAllLists();
            NewExtensionBox.Text = string.Empty;
        }
    }

    private void OnRemoveExtension(object? sender, RoutedEventArgs e)
    {
        if (ExtensionsList.SelectedItem is string s)
        {
            _config.UrlOptions.BlockedExtensions.Remove(s);
            RefreshAllLists();
        }
    }

    
    private void OnAddPort(object? sender, RoutedEventArgs e)
    {
        if (NewPortBox.Value is { } v)
        {
            var port = (int)v;
            if (port > 0 && !_config.HttpsOptions.AllowedPorts.Contains(port))
            {
                _config.HttpsOptions.AllowedPorts.Add(port);
                RefreshAllLists();
            }
        }
    }

        private void OnRemovePort(object? sender, RoutedEventArgs e)
        {
            if (PortsList.SelectedItem is int p)
            {
                _config.HttpsOptions.AllowedPorts.Remove(p);
                RefreshAllLists();
            }
        }
        private void OnRemoveSubnet(object? sender, RoutedEventArgs e)
        {
            if(SubnetsList.SelectedItem is string subnet)
            {
                _config.SubnetOptions.BlockedCidrList.Remove(subnet);
                RefreshAllLists();
            }
        }
    }
}