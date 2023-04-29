# SecuredConfig Demo Web API

## Import dummy.pfx into CurrentUser's Personal Store
Run `Import-DummyCert.ps1` PowerShell script

## appsettings.json contains encrypted password in `Default` ConnectionString
``` json
  "ConnectionStrings": {
    "Default": "Data Source=(local);Initial Catalog=Test;Password={Enc:CN=dummy,NotAfter=2033-04-25:Obb/FVzd2CM584+aoWT7KeOy0aK4QDBwOIyQGq36nM8zQIbOOZom+8c2+OhXf9Mw0BtWc2l1jX4WiUunJq95TzMraRdt12M4PU1JvPvom4ld35/ikTxg6R7Dc12U0qRzIilr/j5pPYrlC3LE4KShRcaee/GuWrdyluF0Cndt7BsqLtHXNtn5EGJb/gCZIyq+hNIsadl5O1IBLHlLRyCUIiAzeoWufXehw66STUAlj3Pfoy4kh8boK6x6Sb4nSzN3IIbzpvdFzKZXLpiNrPew8Ylu40jyxfG6qIbGpdsUmsHjvMhk5/RZHcH9FnUd8ld27fX+6/GcR+ZT6EsC7pwrfw==};User ID=dev;"
  }
```

## Run the demo Web API
Run `dotnet run` under this project

Open the browser and go to http://localhost:5012, You should be able to see the decrypted connection string.
```
Decrypted connection string: Data Source=(local);Initial Catalog=Test;Password=plainValue1;User ID=dev;
```
