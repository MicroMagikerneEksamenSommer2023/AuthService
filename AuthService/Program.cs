using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using AuthService.Models;
using NLog;
using NLog.Web;
using AuthService.Services;

// Opsætter NLog som default loggingtool 
var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

logger.Debug("init main");

try
{
    var builder = WebApplication.CreateBuilder(args);

    // Henter Vault hostname fra dockercompose
    string hostnameVault = Environment.GetEnvironmentVariable("HostnameVault") ?? "vault";

    // Opsætter Vault ved at bruge endpoint fra Vault
    var EndPoint = $"http://{hostnameVault}:8200/";
    var httpClientHandler = new HttpClientHandler();
    httpClientHandler.ServerCertificateCustomValidationCallback =
        (message, cert, chain, sslPolicyErrors) => { return true; };

    // Initaliserer en af auth metoderne
    IAuthMethodInfo authMethod =
        new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

    Console.WriteLine($"Bruger vault på addresen: {EndPoint}");

    // Initaliser vault settings
    var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
    {
        Namespace = "",
        MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler)
        {
            BaseAddress = new Uri(EndPoint)
        }
    };

    // Initaliser vault client
    IVaultClient vaultClient = new VaultClient(vaultClientSettings);

    EnviromentVariables vaultSecrets = vaultSecrets = new EnviromentVariables
    {
        dictionary = new Dictionary<string, string>
        {
            { "secret", "kerrik123456789123456789123456789"},
            { "issuer", "authservice123456789123456789"}
        }
    }; ;

    // Bruger vault client til at læse key-value secrets
    Secret<SecretData> enviromentVariables = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "enviromentVariables", mountPoint: "secret");


    // Initaliser string variables til at gemme miljø secrets
    string? secret = enviromentVariables.Data.Data["secret"].ToString();
    string? issuer = enviromentVariables.Data.Data["issuer"].ToString();

    logger.Info($"Variables loaded in program.cs: Secret: {secret}, Issuer: {issuer}");

    // Opretter en EnviromentVariabable objekt med en dictionary som kan indeholde secrets
    vaultSecrets = new EnviromentVariables
    {
        dictionary = new Dictionary<string, string>
        {
            { "secret", secret },
            { "issuer", issuer }
        }
    };

    // Tilføjer miljøvaribel objekt til projektet som en singletond
    // Det kan tilgåes fra hele projektet
    builder.Services.AddSingleton<EnviromentVariables>(vaultSecrets);


    // tilføjer fuktionalitet som gør det muligt for projektet til at vertificere JWT-tokens
    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = vaultSecrets.dictionary["issuer"],
                IssuerSigningKey =
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(vaultSecrets.dictionary["secret"]))
            };
        });

    // Tilføjer services til projektet.
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddScoped<LoginService>();

    // Tilføjer NLog til projektet
    builder.Logging.ClearProviders();
    builder.Host.UseNLog();

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();

    app.UseAuthentication();

    app.UseAuthorization();

    app.MapControllers();

    app.Run();
}
catch (System.Net.Http.HttpRequestException httpEx)
{
    logger.Error(httpEx, "Http Request error. ");
    throw;
}
catch (Exception ex)
{
    logger.Error(ex, "Stopped program because of exception");
    throw;
}
finally
{
    // Lukker NLog ned
    NLog.LogManager.Shutdown();
}