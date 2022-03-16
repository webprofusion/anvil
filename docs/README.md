# Certes

**The project is a slight fork of https://github.com/fszlin/certes with packaging updates and feature updates.**
The updated package is published to nuget as `Webprofusion.Certes`. 

Certes is an [ACME](https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment)
client runs on .NET 4..6.2+ and .NET Standard 2.0+, supports ACME v2 and wildcard certificates.
It is aimed to provide an easy to use API for managing certificates during deployment processes.

## Usage

Install [Certes](https://www.nuget.org/packages/Webprofusion.Certes/) nuget package into your project:
```PowerShell
Install-Package Webprofusion.Certes
```
or using .NET CLI:
```DOS
dotnet add package Webprofusion.Certes
```

[Let's Encrypt](https://letsencrypt.org/how-it-works/)
is the primary CA we supported.
It's recommend testing against
[staging environment](https://letsencrypt.org/docs/staging-environment/)
before using production environment, to avoid hitting the 
[rate limits](https://letsencrypt.org/docs/rate-limits/).

## Account

Creating new ACME account:
```C#
var acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2);
var account = await acme.NewAccount("admin@example.com", true);

// Save the account key for later use
var pemKey = acme.AccountKey.ToPem();
```
Use an existing ACME account:
```C#
// Load the saved account key
var accountKey = KeyFactory.FromPem(pemKey);
var acme = new AcmeContext(WellKnownServers.LetsEncryptStagingV2, accountKey);
var account = await acme.Account();
```

See [API doc](APIv2.md#accounts) for additional operations.

## Order

Place a wildcard certificate order
*(DNS validation is required for wildcard certificates)*
```C#
var order = await acme.NewOrder(new[] { "*.your.domain.name" });
```

Generate the value for DNS TXT record
```C#
var authz = (await order.Authorizations()).First();
var dnsChallenge = await authz.Dns();
var dnsTxt = acme.AccountKey.DnsTxt(dnsChallenge.Token);
```
Add a DNS TXT record to `_acme-challenge.your.domain.name` 
with `dnsTxt` value.

For non-wildcard certificate, HTTP challenge is also available
```C#
var order = await acme.NewOrder(new[] { "your.domain.name" });
```
## Authorization

Get the **token** and **key authorization string**
```C#
var authz = (await order.Authorizations()).First();
var httpChallenge = await authz.Http();
var keyAuthz = httpChallenge.KeyAuthz;
```

Save the **key authorization string** in a text file,
and upload it to `http://your.domain.name/.well-known/acme-challenge/<token>`

## Validate

Ask the ACME server to validate our domain ownership
```C#
await challenge.Validate();
```

## Certificate

Download the certificate once validation is done
```C#
var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
var cert = await order.Generate(new CsrInfo
{
    CommonName = "your.domain.name",
}, privateKey);
```

Export full chain certification
```C#
var certPem = cert.ToPem();
```

Export PFX
```C#
var pfxBuilder = cert.ToPfx(privateKey);
var pfx = pfxBuilder.Build("my-cert", "abcd1234");
```

Check the [APIs](APIv2.md) for more details.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags](https://github.com/fszlin/certes/tags) on this repository. 

Also check the [changelog](CHANGELOG.md) to see what's we are working on.
