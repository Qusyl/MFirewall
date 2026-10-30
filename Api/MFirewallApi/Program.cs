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
using MFirewallApp.Dto;
using MFirewallApp.Service.Auth;
using Infrastructure.IdentityUser;
using MFirewallApp;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

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




builder.Services.AddProblemDetails();

builder.Services.AddAuthorization();
builder.Services.AddHttpContextAccessor();

builder.Services.AddHostedService<PacketCaptureService>();
builder.Services.AddHostedService<ReportSender>();
builder.Services.AddHostedService<ConnectionSender>();

builder.Services.AddSingleton<IConnectionTracker, ConnectionTracker>();
builder.Services.AddSingleton<ReportQueue>();
builder.Services.AddSingleton<ConnectionQueue>();
builder.Services.AddSingleton<IPasswordHasher, PasswordHashService>();

builder.Services.AddScoped<IPacketCaptureReceiver, LinuxPacketCaptureReceiver>();
builder.Services.AddScoped<IPacketProcessingService, PacketProcessingService>();
builder.Services.AddScoped<IRuleService, RuleService>();
builder.Services.AddScoped<MFirewallApp.Interface.IAuthenticationService, MFirewallApp.Service.Auth.AuthenticationService>();
builder.Services.AddScoped<ITokenService, TokenService>();
builder.Services.AddScoped<IIdentityService, IdentityUserService>();
builder.Services.AddScoped<IProxyService, HttpProxyService>();
builder.Services.AddScoped<IProxyPolicyService, ProxyPolicyService>();

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(opt =>
{
    opt.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),

        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],

        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],

        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };
});
builder.Services.AddCors(opt =>
{
    opt.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyHeader()
        .AllowAnyMethod()
        .AllowAnyOrigin();
    });
});


builder.Services.AddDbContext<AppDbContext>(opt =>
{
    opt.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

builder.Services.AddSignalR();

builder.Services.AddExceptionHandler<MFirewallExceptionHandler>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseExceptionHandler();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}



app.UseHttpsRedirection();
app.UseRouting();

app.UseCors("AllowAll");


app.UseMiddleware<HttpProxyValidateMiddleware>();

// app.UseMiddleware<JwtTokenMiddleware>();
app.UseAuthorization();
var auth = app.MapGroup("/auth").WithTags("Auth");

app.MapPost("/register", async (UserRegistrationDto dto, [FromServices] MFirewallApp.Interface.IAuthenticationService svc) =>
{
    var result = await svc.RegisterAsync(dto);
    return result.IsSuccess ?
    Results.Ok(new { token = result.Value }) :
    Results.BadRequest(new { error = result.Error });
})
.RequireRateLimiting("auth");

app.MapPost("/login", async (UserLoginDto dto,[FromServices] MFirewallApp.Interface.IAuthenticationService svc) =>
{
    var result = await svc.LoginAsync(dto);

    return result.IsSuccess ?
    Results.Ok(new { token = result.Value}) :
    Results.Json(new { error = "Invalid credentials"}, statusCode: 401);
});
app.MapGet("/status",() =>
{
    return Results.Ok();
});

app.MapHub<LoggerHub>("/logger");
app.Run();





