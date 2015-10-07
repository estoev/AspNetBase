using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNetBase.DAL;
using AspNetBase.Domain;
using CsQuery.ExtensionMethods.Internal;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Facebook;
using Microsoft.Owin.Security.Google;
using Microsoft.Owin.Security.Twitter;
using Owin;

namespace AspNetBase
{
    public partial class Startup
    {
        internal static IDataProtectionProvider DataProtectionProvider { get; private set; }

        public void ConfigureAuth(IAppBuilder app)
        {
            DataProtectionProvider = app.GetDataProtectionProvider();

            // Configure the db context and user manager to use a single instance per request
            app.CreatePerOwinContext(DataContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
                                        {
                                            AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                                            LoginPath = new PathString("/Account/Login"),
                                            Provider = new CookieAuthenticationProvider
                                                       {
                                                           OnValidateIdentity =
                                                               SecurityStampValidator
                                                               .OnValidateIdentity<ApplicationUserManager, User>(
                                                                   TimeSpan.FromMinutes(30),
                                                                   (manager, user) =>
                                                               user.GenerateUserIdentityAsync(manager)),
                                                           //OnException = context => { }
                                                       }
                                        });

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            var settings = Properties.Settings.Default;
            if (!string.IsNullOrEmpty(settings.TwitterConsumerKey) &&
                !string.IsNullOrEmpty(settings.TwitterConsumerSecret))
            {
                var twitterOptions = new TwitterAuthenticationOptions
                {
                    ConsumerKey = settings.TwitterConsumerKey,
                    ConsumerSecret = settings.TwitterConsumerSecret,
                    BackchannelCertificateValidator =
                        new CertificateSubjectKeyIdentifierValidator(new[]
                        {
                            "A5EF0B11CEC04103A34A659048B21CE0572D7D47", // VeriSign Class 3 Secure Server CA - G2
                            "0D445C165344C1827E1D20AB25F40163D8BE79A5", // VeriSign Class 3 Secure Server CA - G3
                            "7FD365A7C2DDECBBF03009F34339FA02AF333133", // VeriSign Class 3 Public Primary Certification Authority - G5
                            "39A55D933676616E73A761DFA16A7E59CDE66FAD", // Symantec Class 3 Secure Server CA - G4
                            "4eb6d578499b1ccf5f581ead56be3d9b6744a5e5", // VeriSign Class 3 Primary CA - G5
                            "5168FF90AF0207753CCCD9656462A212B859723B", // DigiCert SHA2 High Assurance Server C‎A 
                            "B13EC36903F8BF4701D498261A0802EF63642BC3"  // DigiCert High Assurance EV Root CA
                        })
                };

                app.UseTwitterAuthentication(twitterOptions);
            }

            if (!string.IsNullOrEmpty(settings.FacebookAppId) &&
                !string.IsNullOrEmpty(settings.FacebookAppSecret))
            {
                var facebookOptions = new FacebookAuthenticationOptions
                {
                    AppId = settings.FacebookAppId,
                    AppSecret = settings.FacebookAppSecret
                };
                facebookOptions.Scope.Add("email");

                app.UseFacebookAuthentication(facebookOptions);
            }

            if (!string.IsNullOrEmpty(settings.GoogleClientId) &&
                !string.IsNullOrEmpty(settings.GoogleClientSecret))
            {
                var googleOptions = new GoogleOAuth2AuthenticationOptions
                {
                    ClientId = settings.GoogleClientId,
                    ClientSecret = settings.GoogleClientSecret,
                    Provider = new GoogleOAuth2AuthenticationProvider()
                    {
                        OnAuthenticated = context =>
                        {
                            context.Identity.AddClaim(new Claim("urn:google:name",
                                context.Identity.FindFirstValue(ClaimTypes.Name)));
                            context.Identity.AddClaim(new Claim("urn:google:email",
                                context.Identity.FindFirstValue(ClaimTypes.Email)));

                            // This following line is need to retrieve the profile image
                            context.Identity.AddClaim(new Claim("urn:google:accesstoken", context.AccessToken,
                                ClaimValueTypes.String, "Google"));

                            return Task.FromResult(0);
                        }
                    }
                };

                app.UseGoogleAuthentication(googleOptions);
            }
        }
    }
}