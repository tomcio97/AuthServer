using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Collections.Immutable;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Controllers
{
    [ApiController]
    public class AuthorizationController : Controller
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictScopeManager _scopeManager;
        private readonly AuthorizationService _authService;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;
        public AuthorizationController(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictScopeManager scopeManager,
            AuthorizationService authService,
            IOpenIddictAuthorizationManager authorizationManager)
        {
            _applicationManager = applicationManager;
            _scopeManager = scopeManager;
            _authService = authService;
            _authorizationManager = authorizationManager;
        }

        [HttpGet("~/connect/authorize")]
        [HttpPost("~/connect/authorize")]
        public async Task<IActionResult> Authorize()
         {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            var parameters = _authService.ParseOAuthParameters(HttpContext, new List<string> { Parameters.Prompt });

            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);


            string provider = HttpContext.Request.Query["provider"];

            if (!_authService.IsAuthenticated(result, request))
            {
                return Challenge(properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters)
                }, provider ?? CookieAuthenticationDefaults.AuthenticationScheme);
            }

            var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
                              throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

            var userEmail = result.Principal.FindFirst(ClaimTypes.Email)!.Value;
            var userId = result.Principal.FindFirst(ClaimTypes.NameIdentifier)!.Value;
            var userName = result.Principal.FindFirst(ClaimTypes.Name)!.Value;

            if (userId == null)
            {
                return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [Parameters.Error] = Errors.InvalidGrant,
                    [Parameters.ErrorDescription] = "Nie udało się uwierzytelnić użytkownika."
                }));
            }

            var identity = new ClaimsIdentity(
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userEmail)
                .SetClaim(Claims.Name, userName)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("~/connect/token")]
        public async Task<IActionResult> Exchange()
        {
            var request = HttpContext.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

            if (!request.IsAuthorizationCodeGrantType() && 
                !request.IsRefreshTokenGrantType())
                throw new InvalidOperationException("The specified grant type is not supported.");

            var result = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            var userId = result.Principal.GetClaim(Claims.Subject);
            var userEmail = result.Principal.GetClaim(Claims.Email);
            var userName = result.Principal.GetClaim(Claims.Name);

            if (string.IsNullOrEmpty(userId))
            {
                return Forbid(
                    authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Cannot find user from the token."
                    }));
            }

            var identity = new ClaimsIdentity(result.Principal.Claims,
                authenticationType: TokenValidationParameters.DefaultAuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            identity.SetClaim(Claims.Subject, userId)
                .SetClaim(Claims.Email, userEmail)
                .SetClaim(Claims.Name, userName)
                .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

            identity.SetDestinations(c => AuthorizationService.GetDestinations(identity, c));

            identity.SetScopes(request.GetScopes());
            identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

            return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpGet("~/connect/logout")]
        [HttpPost("~/connect/logout")]
        public async Task<IActionResult> LogoutPost()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
        }

        //[HttpGet("AddApplication")]
        //public async Task<IActionResult> AddAplication()
        //{
        //    await _applicationManager.CreateAsync(new OpenIddictApplicationDescriptor
        //    {
        //        ClientId = "my-client4",
        //        ClientSecret = "client-secret",
        //        RedirectUris = { new Uri("https://localhost:7002/swagger/oauth2-redirect.html") },
        //        Permissions =
        //{
        //OpenIddictConstants.Permissions.Endpoints.Authorization,
        //OpenIddictConstants.Permissions.Endpoints.Token,
        //OpenIddictConstants.Permissions.Scopes.Email,

        //OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
        //OpenIddictConstants.Permissions.ResponseTypes.Code,
        
        //},

        //    });

        //    return Ok();
        //}

        //[HttpGet("AddScope")]
        //public async Task<IActionResult> AddScope()
        //{
        //    await _scopeManager.CreateAsync(new OpenIddictScopeDescriptor()
        //    {
        //        Name = "api",
        //        Resources = { "api" }
        //    });

        //    return Ok();
        //}
    }
}
