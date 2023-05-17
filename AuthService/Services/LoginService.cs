using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using MongoDB.Driver;
using MongoDB.Bson;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;
using AuthService.Models;
using System.Net.Http;

namespace AuthService.Services
{
    public class LoginService
    {
        private readonly IConfiguration _config;
        public ILogger<LoginService> _logger { get; }

        private readonly HttpClient _httpClient;

        //Intialiser miljøvariabler - Bruges til vault: 
        private readonly string? _secret; 

        private readonly string? _issuer; 

        public LoginService(IConfiguration config, ILogger<LoginService> logger, HttpClient httpClient, EnviromentVariables vaultSecrets)
        {
            _config = config;
            _logger = logger;

            //Miljøvariabel - burde være det her format: http://customerservice:8201
            httpClient.BaseAddress = new Uri(_config["CustomerServiceBassAddress"]);
            _httpClient = httpClient;

            //henter secrets fra indjected fra EviromentVariable klassen
            _secret = vaultSecrets.dictionary["secret"];
            _issuer = vaultSecrets.dictionary["issuer"];

            _logger.LogInformation($"LoginService oprettet med følgende konfiguration: BaseAddress: {httpClient.BaseAddress}, Secret: {_secret}, Issuer: {_issuer}");
        }

        public async Task<IActionResult> Login(LoginInfo login)
        {
            bool LoginConfirmed = false;
            var respons = await _httpClient.GetAsync("/cutomerservice/v1/checkcredentials");

            // Hvis anmodningen er blevet udført med succes
            if (respons.IsSuccessStatusCode)
            {
                var result = await respons.Content.ReadAsStringAsync();
                LoginConfirmed = Boolean.Parse(result);
            }

            // Hvis login er bekræftet
            if (LoginConfirmed)
            {
                var token = GenerateJwtToken(login.Email);

                 // Logning af loginoplysninger
                 _logger.LogInformation($"Login bekræftet for customer på email: {login.Email}");

                // Returnerer en 200 OK respons med token i JSON-format
                return new OkObjectResult(new { token });
            }
            else 
            { 
                // Logning af loginoplysninger
                 _logger.LogInformation($"Login mislykkedes for customer på email: {login.Email}");

                // Returnerer en 401 Unauthorized respons
                return new UnauthorizedResult();
            }

        }

    public async Task<IActionResult> ValidateJwtToken(string token)
    {
        // Hvis tokenet er tomt eller null, sendes en 400 BadRequest statuskode med en fejlmeddelelse.
        if (string.IsNullOrEmpty(token))
            return new BadRequestObjectResult("Invalid token submitted.");

        // Opretter en JwtSecurityTokenHandler og henter hemmeligheden fra app-konfigurationen.
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_secret!);
        try
        {
            // Validerer JWT-tokenet ved at bruge hemmeligheden og andre tokenvalideringsparametre.
            // Hvis tokenet er gyldigt, udtrækkes bruger-ID'en fra tokenet og returneres som svar på anmodningen.
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                //angiver, at issuerens signeringssøgle skal valideres.
                ValidateIssuerSigningKey = true,
                //angiver den symmetriske sikkerhedsnøgle, der bruges til at validere tokenets signatur.
                IssuerSigningKey = new SymmetricSecurityKey(key),
                //angiver, at issuernavn (udstedende autoritet) ikke skal valideres. 
                ValidateIssuer = false,
                //angiver, at målgruppen (audience) ikke skal valideres. 
                ValidateAudience = false,
                //angiver, at ingen tidsoverskridelse (skew) skal tillades under valideringen af tokenets udløbstid og udstedelsestidspunkt.
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            //Efter validering af tokenet får vi adgang til det validerede token.
            var jwtToken = (JwtSecurityToken)validatedToken;
            var accountId = jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            return new OkObjectResult(accountId);
        }
        catch (Exception ex)
        {
            // Hvis valideringen fejler, logges en fejlmeddelelse, og der returneres en 404 Not Found statuskode.
            _logger.LogError(ex, ex.Message);
            return new StatusCodeResult(404);
        }
    }

    private string GenerateJwtToken(string email)
    {
        // Opretter en hemmelighed baseret på app-konfigurationens JWT-secret --> sercret = miljøvariabel
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret));
        // Opretter et SigningCredentials-objekt, der bruger hemmeligheden og HMACSHA256-algoritmen.
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        // Opretter en bruger-ID-claim til at inkludere i tokenet.
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, email)
        };
        // Opretter en JWT, der inkluderer udstederen (Issuer), publikum (Audience), brugerens claims og udløbstiden.
        // Tokenet underskrives med credentials-objektet. --> issuer = miljøvariabel
        var token = new JwtSecurityToken(
            _issuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);

        // logger en besked til logfilen, der indeholder oplysninger om hemmeligheden og udstederen, der bruges til at generere en JSON Web Token (JWT).
        _logger.LogInformation($"Generate token info: Secret: {_secret}, Issuer: {_issuer}");

        // Returnerer tokenet i form af en JWT-streng.
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
}