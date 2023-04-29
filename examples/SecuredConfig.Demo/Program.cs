var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSecuredConfiguration();
var app = builder.Build();

app.MapGet("/", (IConfiguration configuration) => $"Decrypted connection string: {configuration.GetConnectionString("Default")}");

app.Run();
