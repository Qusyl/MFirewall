using MFirewallApi.ExceptionHandler;
using MFirewallApp.Interface;
using MFirewallApp.Linux;
using MFirewallApp.Rules;
using MFirewallApp.Service;
using Infrastructure.Extensions;
using MFirewallApp.FileSystem;
using MFirewallApp.Rules.StatefulRule;

using MFirewallApp.Hubs;
using MFirewallApi.Middlewares;
using MFirewallApp.Crypto.Token;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using MFirewallApp.Validators;
using Microsoft.AspNetCore.Authentication;
using Infrastructure.DbContext;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// var contentPath = builder.Environment.ContentRootPath;  production
var contentPath = "/home/denis/Documents/Kursovie/Security/Api/MFirewallApi";
var configPath = Path.Combine(contentPath, "configuration", "firewall_configuration.json");
var httpConfigPath = Path.Combine(contentPath, "configuration", "http_proxy_configuration.json");

builder.Configuration
.SetBasePath(AppContext.BaseDirectory)
.AddJsonFile("appsettings.json", optional: false,  reloadOnChange: true)
.AddJsonFile(configPath, optional: false, reloadOnChange: true)
.AddJsonFile(httpConfigPath, optional: false, reloadOnChange: true);


builder.Services.AddRules();



builder.Services.Configure<FirewallConfiguration>(builder.Configuration.GetSection("FirewallConfiguration"));
builder.Services.Configure<HttpProxyConfiguration>(builder.Configuration.GetSection("HttpProxyConfiguration"));


builder.Services
.AddOptions<JwtOptions>()
.Bind(builder.Configuration.GetSection(JwtOptions.SectionName))
.ValidateDataAnnotations()
.Validate(opt => opt.ExpirationTime <= 60, "Expiration must be <= 60 minutes")
.ValidateOnStart();


builder.Services.AddOpenApi();

builder.Services.AddProblemDetails();
builder.Services.AddAuthorization(opts =>
{
    opts.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
    .RequireAuthenticatedUser()
    .Build();
});

builder.Services.AddHostedService<PacketCaptureService>();
builder.Services.AddHttpContextAccessor();

builder.Services.AddSingleton<IConnectionTracker, ConnectionTracker>();
builder.Services.AddSingleton<ReportQueue>();
builder.Services.AddSingleton<ConnectionQueue>();
builder.Services.AddSingleton<JwtValidator>();
builder.Services.AddCors(opt =>
{
    opt.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyHeader()
        .AllowAnyMethod()
        .AllowAnyOrigin();
    });
});

builder.Services.AddScoped<IPacketCaptureReceiver, LinuxPacketCaptureReceiver>();
builder.Services.AddHostedService<ReportSender>();
builder.Services.AddHostedService<ConnectionSender>();


builder.Services.AddScoped<IPacketProcessingService, PacketProcessingService>();
builder.Services.AddScoped<IRuleService, RuleService>();
builder.Services.AddScoped<IProxyService, HttpProxyService>();
builder.Services.AddScoped<IProxyPolicyService, ProxyPolicyService>();
builder.Services.AddDbContext<AppDbContext>(opt =>
{
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddSignalR();

builder.Services.AddExceptionHandler<MFirewallExceptionHandler>();

var app = builder.Build();

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}



app.UseHttpsRedirection();
app.UseRouting();

app.UseCors("AllowAll");


app.UseMiddleware<HttpProxyValidateMiddleware>();

app.UseMiddleware<JwtTokenMiddleware>();
app.UseAuthorization();

app.MapGet("/status",() =>
{
    return Results.Ok();
});

app.MapHub<LoggerHub>("/logger");
app.Run();





