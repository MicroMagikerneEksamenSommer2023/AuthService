using MongoDB.Driver;
using System.Threading.Tasks;

namespace AuthService.Services
{
    // En serviceklasse, der håndterer kundeobjekter i MongoDB-databasen.
    public class CustomerService
    {
        private readonly IMongoCollection<LoginInfo> _customer;

        public CustomerService(IConfiguration config)
        {
            // Opretter en ny MongoDB-klient med den angivne forbindelsesstreng og databasekonfiguration.
            var mongoClient = new MongoClient(config["connectionsstring"]);
            var database = mongoClient.GetDatabase(config["database"]);

            // Henter kundesamlingen fra databasen.
            _customer = database.GetCollection<LoginInfo>(config["collection"]);
        }

        // Returnerer en kunde i databasen med det angivne brugernavn.
        public async Task<LoginInfo> GetCustomerByEmail(string email)
        {
            return await _customer.Find(u => u.Email == email).FirstOrDefaultAsync();
        }
    }

}