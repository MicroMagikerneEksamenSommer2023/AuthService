using System;
namespace AuthService.Models
{
	public class EnviromentVariables
	{
		//Denne dictionary kan bruges til at gemme miljøvariabler:
		public Dictionary<string, string> dictionary { get; set; }

		public EnviromentVariables()
		{
		}
	}
}
