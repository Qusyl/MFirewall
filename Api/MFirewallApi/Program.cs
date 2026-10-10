using MFirewallApi.ExceptionHandler;
using MFirewallApp.Interface;
using MFirewallApp.Linux;
using MFirewallApp.Rules;
using MFirewallApp.Service;
using Infrastructure.Extensions;
using MFirewallApp.FileSystem;

var builder = WebApplication.CreateBuilder(args);

// var contentPath = builder.Environment.ContentRootPath;  production
var contentPath = "/home/denis/Documents/Kursovie/Security/Api/MFirewallApi";
var configPath = Path.Combine(contentPath, "configuration", "rule_configuration.json");
builder.Configuration
.SetBasePath(AppContext.BaseDirectory)
.AddJsonFile(configPath, optional: false, reloadOnChange: true);

builder.Services.AddRules();



builder.Services.Configure<RuleConfiguration>(builder.Configuration.GetSection("RuleConfiguration"));
builder.Services.AddOpenApi();

builder.Services.AddProblemDetails();

builder.Services.AddHostedService<PacketCaptureService>();

builder.Services.AddScoped<IPacketCaptureReceiver, LinuxPacketCaptureReceiver>();

builder.Services.AddScoped<IRuleService, RuleService>();

builder.Services.AddExceptionHandler<MFirewallExceptionHandler>();

var app = builder.Build();

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();


app.Run();





