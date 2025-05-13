using IdentityServer.Data;
using IdentityServer.Data.Repository;
using IdentityServer.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Extensions
{
    public static class DependencyInjection
    {
        public static IServiceCollection RegisterServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));
                options.UseOpenIddict();
            });

            services.AddIdentity<ApplicationUser, ApplicationRole>(o =>
            {
                o.SignIn.RequireConfirmedAccount = !true;
                o.Password = new PasswordOptions
                {
                    RequireDigit = false,
                    RequiredLength = 1,
                    RequiredUniqueChars = 0,
                    RequireLowercase = false,
                    RequireNonAlphanumeric = false,
                    RequireUppercase = false
                };
            })
            .AddDefaultTokenProviders()
            .AddEntityFrameworkStores<ApplicationDbContext>();

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                            .UseDbContext<ApplicationDbContext>();
                })
                .AddServer(options =>
                {
                    options.SetAuthorizationEndpointUris("connect/authorize")
                            .SetLogoutEndpointUris("connect/logout")
                            .SetTokenEndpointUris("connect/token");

                    options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "api");

                    options.AllowAuthorizationCodeFlow();

                    options.AddDevelopmentEncryptionCertificate()
                            .AddDevelopmentSigningCertificate();

                    options.UseAspNetCore()
                            .EnableAuthorizationEndpointPassthrough()
                            .EnableLogoutEndpointPassthrough()
                            .EnableTokenEndpointPassthrough();

                    options.DisableAccessTokenEncryption();
                }).AddClient(options =>
                {
                    options.AllowAuthorizationCodeFlow();
                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    options.UseAspNetCore()
                           .EnableRedirectionEndpointPassthrough();

                    options.UseSystemNetHttp();

                    // Register the Google integration.
                    options.UseWebProviders().AddGoogle(options =>
                        {
                            options.SetClientId(configuration["ExternalProviders:Google:ClientId"])
                                      .SetClientSecret(configuration["ExternalProviders:Google:ClientSecret"])
                                      .SetRedirectUri(configuration["ExternalProviders:Google:RedirectUri"])
                                      .SetProviderDisplayName(configuration["ExternalProviders:Google:DisplayName"])
                                      .AddScopes(configuration["ExternalProviders:Google:Scopes"]);
                        });
                }).AddValidation(options =>
                {
                    options.UseLocalServer();
                    options.UseAspNetCore();

                });

            services.AddControllers();
            services.AddRazorPages();

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(c =>
                {
                    c.LoginPath = "/Identity/Account/Login";
                });

            services.AddTransient<AuthorizationService>();

            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen();

            services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                {
                    policy.WithOrigins("https://localhost:7002")
                        .AllowAnyHeader();

                    policy.WithOrigins("http://localhost:3000")
                        .AllowAnyHeader();
                });
            });

            services.AddTransient<ClientAppRepository>();
            services.AddTransient<ScopesRepository>();
            services.AddScoped<IdentityDataSeeder>();

            return services;
        }
    }
}