using MFirewallApi.ExceptionHandler;
using MFirewallApp.Interface;
using MFirewallApp.Linux;
using MFirewallApp.Rules;
using MFirewallApp.Service;
using Infrastructure.Extensions;
using MFirewallApp.FileSystem;
using MFirewallApp.Rules.StatefulRule;

using MFirewallApp.Hubs;

var builder = WebApplication.CreateBuilder(args);

// var contentPath = builder.Environment.ContentRootPath;  production
var contentPath = "/home/denis/Documents/Kursovie/Security/Api/MFirewallApi";
var configPath = Path.Combine(contentPath, "configuration", "firewall_configuration.json");
builder.Configuration
.SetBasePath(AppContext.BaseDirectory)
.AddJsonFile(configPath, optional: false, reloadOnChange: true);

builder.Services.AddRules();



builder.Services.Configure<FirewallConfiguration>(builder.Configuration.GetSection("FirewallConfiguration"));
builder.Services.AddOpenApi();

builder.Services.AddProblemDetails();

builder.Services.AddHostedService<PacketCaptureService>();

builder.Services.AddSingleton<IConnectionTracker, ConnectionTracker>();
builder.Services.AddSingleton<ReportQueue>();
builder.Services.AddSingleton<ConnectionQueue>();

builder.Services.AddScoped<IPacketCaptureReceiver, LinuxPacketCaptureReceiver>();
builder.Services.AddHostedService<ReportSender>();


builder.Services.AddScoped<IPacketProcessingService, PacketProcessingService>();
builder.Services.AddScoped<IRuleService, RuleService>();

builder.Services.AddSignalR();

builder.Services.AddExceptionHandler<MFirewallExceptionHandler>();

var app = builder.Build();

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.MapGet("/status",() =>
{
    return Results.Ok();
});

app.MapHub<LoggerHub>("/logger");
app.Run();





