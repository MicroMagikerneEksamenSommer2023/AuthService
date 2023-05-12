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

namespace AuthService.Services
{
    public class LoginService
    {
        private readonly CustomerService _customerService;
        private readonly IConfiguration _config;
        public ILogger<LoginService> Logger { get; }

        public LoginService(CustomerService customerService, IConfiguration config, ILogger<LoginService> logger)
        {
            _customerService = customerService;
            _config = config;
            Logger = logger;
        }

        public async Task<IActionResult> Login(LoginInfo login)
        {
            // Logger information om, hvornår metoden blev kaldt, og med hvilke argumenter
            Logger.LogInformation("Metoden: Login(LoginModel login) kaldt klokken: {DT}", DateTime.UtcNow.ToLongTimeString());

            // Henter brugeren, der matcher med brugernavnet i LoginModel fra databasen
            LoginInfo customer = await _customerService.GetCustomerByEmail(login.Email);
            // Logger login-oplysningerne for brugeren
            Logger.LogInformation($"Loginoplysninger\n\tUsername: {customer.Email}\n\tPassword: {customer.Password}");

            // Hvis brugeren ikke findes i databasen, eller brugernavnet i LoginModel ikke matcher brugernavnet i databasen, så returneres en 401 Unauthorized respons
            if (customer == null || customer.Email != login.Email) { return new UnauthorizedResult(); }
        // Genererer en JSON Web Token for brugeren
        var token = GenerateJwtToken(customer.Email);

        // Returnerer en 200 OK respons med token i JSON-format
        return new OkObjectResult(new { token });
    }

    public async Task<IActionResult> ValidateJwtToken(string token)
    {
        // Hvis tokenet er tomt eller null, sendes en 400 BadRequest statuskode med en fejlmeddelelse.
        if (string.IsNullOrEmpty(token))
            return new BadRequestObjectResult("Invalid token submitted.");

        // Opretter en JwtSecurityTokenHandler og henter hemmeligheden fra app-konfigurationen.
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_config["secret"]!);
        try
        {
            // Validerer JWT-tokenet ved at bruge hemmeligheden og andre tokenvalideringsparametre.
            // Hvis tokenet er gyldigt, udtrækkes bruger-ID'en fra tokenet og returneres som svar på anmodningen.
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);
            var jwtToken = (JwtSecurityToken)validatedToken;
            var accountId = jwtToken.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            return new OkObjectResult(accountId);
        }
        catch (Exception ex)
        {
            // Hvis valideringen fejler, logges en fejlmeddelelse, og der returneres en 404 Not Found statuskode.
            Logger.LogError(ex, ex.Message);
            return new StatusCodeResult(404);
        }
    }

    private string GenerateJwtToken(string username)
    {
        // Opretter en hemmelighed baseret på app-konfigurationens JWT-secret --> sercret = miljøvariabel
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["secret"]));
        // Opretter et SigningCredentials-objekt, der bruger hemmeligheden og HMACSHA256-algoritmen.
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        // Opretter en bruger-ID-claim til at inkludere i tokenet.
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, username)
        };
        // Opretter en JWT, der inkluderer udstederen (Issuer), publikum (Audience), brugerens claims og udløbstiden.
        // Tokenet underskrives med credentials-objektet. --> issuer = miljøvariabel
        var token = new JwtSecurityToken(
            _config["issuer"],
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);

        // logger en besked til logfilen, der indeholder oplysninger om hemmeligheden og udstederen, der bruges til at generere en JSON Web Token (JWT).
        Logger.LogInformation($"Generate token info: Secret: {_config["secret"]}, Issuer: {_config["issuer"]}");

        // Returnerer tokenet i form af en JWT-streng.
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
}