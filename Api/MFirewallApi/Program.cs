using MFirewallApi.ExceptionHandler;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

builder.Services.AddProblemDetails();

builder.Services.AddExceptionHandler<MFirewallExceptionHandler>();

var app = builder.Build();
app.UseExceptionHandler();
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();



app.Run();


