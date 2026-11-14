using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

using Avalonia.Threading;

namespace MFirewallAppUI;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
        var _ = typeof(Avalonia.Controls.DataGrid);
    }

    public override async void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
    {
        var main = new MainWindow();
        desktop.MainWindow = main;

        
        main.Opened += async (_, _) =>
        {
            var auth = new AuthorizationWindow();
            await auth.ShowDialog(main);   

            if (!auth.IsAuthorized)
            {
                desktop.Shutdown();
                return;
            }

            main.IsAdmin = auth.IsAdmin;
            main.IsAuthorized = auth.IsAuthorized;
          
        };
    }

        base.OnFrameworkInitializationCompleted();
    }
}