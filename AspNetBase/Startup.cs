using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(AspNetBase.Startup))]
namespace AspNetBase
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
