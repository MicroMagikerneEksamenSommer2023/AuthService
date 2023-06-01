# AuthService API-dokumentation

Denne dokumentation beskriver de tilgængelige endpoints og deres funktionalitet i AuthService API'en.

## Login

Autentificerer en bruger ved at validere e-mailadresse og adgangskode.

- URL: `/authservice/v1/login`
- Metode: `POST`
- Parametre: 
  - `LoginInfo` (JSON): Et objekt, der indeholder brugerens e-mailadresse og adgangskode.
    ```json
    {
        "email": "henrik@example.com",
        "accessCode": "MinKode123"
    }
    ```
- Respons: 
  - En statuskode, der indikerer succes eller fejl.

## NginxAuth

Tjekker gyldigheden af en brugers session ved at kræve autorisation.

- URL: `/authservice/v1/gateway`
- Metode: `GET`
- Autorisation: Kræver gyldig session.
- Respons: 
  - En statuskode, der indikerer succes eller fejl.

## ValidateJwtToken

Validerer en JWT-token for at bekræfte brugerens autentificering.

- URL: `/authservice/v1/validate`
- Metode: `POST`
- Parametre: 
  - `token` (JSON): En JWT-token.
- Respons: 
  - En statuskode, der indikerer gyldigheden af token.

## Version

Henter versionsoplysninger om AuthService.

- URL: `/authservice/v1/version`
- Metode: `GET`
- Respons: 
  - En liste med metadata om assembly'en, der repræsenterer versionen af AuthService.

### LoginInfo

Objektet `LoginInfo` indeholder brugerens e-mailadresse og adgangskode.

Egenskaber:

- `email` (string): Brugerens e-mailadresse.
- `accessCode` (string): Brugerens adgangskode.

## EnviromentVariables

Klassen `EnviromentVariables` repræsenterer en samling af miljøvariabler.

Egenskaber:

- `dictionary` (Dictionary&lt;string, string&gt;): En dictionary, der gemmer miljøvariabler som nøgle-værdi-par.

### Constructor

- `EnviromentVariables()`: Konstruktøren opretter en ny instans af `EnviromentVariables`.

## Sådan oprettes en ny kunde - JSON-format

For at oprette en ny kunde ved hjælp af API'en skal du sende følgende JSON-data som en del af din anmodning:

```json
{
    "firstName": "Hanne",
    "lastName": "Gylling",
    "gender": "Kvinde",
    "birthDate": "1998-05-11T16:31:05.768Z",
    "address": "pilkjærsvej 2",
    "postalCode": "8210",
    "city": "Aarhus V",
    "country": "DK",
    "telephone": "12341234",
    "email": "hagy@haha.dk",
    "accessCode": "SCRUMMASTER123"
}

## CheckCredentials - JSON-format

Når du sender en anmodning til `/checkcredentials` endpoint, skal du inkludere følgende JSON-data som en del af din anmodning:

```json
{
    "email": "henrik@example.com",
    "accessCode": "MinKode123"
}

Bemærk, at du stadig skal erstatte værdierne i JSON-dataen med de faktiske værdier, du ønsker at bruge til at kontrollere brugerens legitimationsoplysninger.
