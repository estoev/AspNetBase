using System.Web.Configuration;
using AspNetBase.DAL;
using AspNetBase.DependencyResolution.Tasks;
using AspNetBase.Services;

namespace AspNetBase
{
    public class SiteInit : IRunAtStartup
    {
        public SiteInit(DataContext db)
        {
        }

        public void Execute()
        {
        }
    }
}