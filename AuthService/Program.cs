using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;


var builder = WebApplication.CreateBuilder(args);

// Hent værdien af miljøvariablerne "Secret" og "Issuer" eller sæt dem til "none", hvis de ikke findes
string mySecret = Environment.GetEnvironmentVariable("Secret") ?? "none";
string myIssuer = Environment.GetEnvironmentVariable("Issuer") ?? "none";

// Tilføj JWT authentication til tjenestesamlingen med de angivne valideringsparametre
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            // Valider udsteder
            ValidateIssuer = true,
            // Valider modtager
            ValidateAudience = true,
            // Valider levetid
            ValidateLifetime = true,
            // Valider signatur af udsteder
            ValidateIssuerSigningKey = true,
            // Godkendt udsteder
            ValidIssuer = myIssuer,
            // Godkendt modtager
            ValidAudience = "http://localhost",
            // Signeringsnøgle
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret))
        };
    });

// Tilføj services til containeren
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();


// Konfigurer HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Omdiriger HTTP forespørgsler til HTTPS
app.UseHttpsRedirection();

// Brug authentication
app.UseAuthentication();

// Brug authorization
app.UseAuthorization();

// Map HTTP forespørgsler til de angivne controllers
app.MapControllers();

app.Run();