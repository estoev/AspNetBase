using System;
using System.Data.Entity.Validation;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;
using Elmah;
using AspNetBase.DAL;
using AspNetBase.DependencyResolution;
using AspNetBase.DependencyResolution.Tasks;
using AspNetBase.Helpers;
using StructureMap.Web.Pipeline;

namespace AspNetBase
{
    public class MvcApplication : HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            ModelBinders.Binders.DefaultBinder = new CustomModelBinder();
            IoC.Init();
            ValidatorConfig.Init();

            // Run other startup tasks
            foreach (var task in IoC.StructureMapResolver.Container.GetAllInstances<IRunAtStartup>())
            {
                task.Execute();
            }
        }

        protected void Application_End()
        {
        }

        public void Application_BeginRequest(Object sender, EventArgs e)
        {
            IoC.StructureMapResolver.CreateNestedContainer();

            foreach (var task in IoC.StructureMapResolver.CurrentNestedContainer.GetAllInstances<IRunOnEachRequest>())
            {
                task.Execute();
            }
        }

        public void Application_EndRequest(Object sender, EventArgs e)
        {
            try
            {
                foreach (var task in IoC.StructureMapResolver.CurrentNestedContainer.GetAllInstances<IRunAfterEachRequest>())
                {
                    task.Execute();
                }
            }
            finally
            {
                HttpContextLifecycle.DisposeAndClearAll();
                IoC.StructureMapResolver.DisposeNestedContainer();
            }

            DataContext.DisposeCurrent();
        }

        public void Application_Error(Object sender, EventArgs e)
        {
            try
            {
                var ex = Server.GetLastError();
                if (ex.GetType() == typeof (DbEntityValidationException))
                {
                    // Get more detailed db entity validation exception

                    var dbex = (DbEntityValidationException) ex;
                    var errorMessages = (from eve in dbex.EntityValidationErrors
                        let entity = eve.Entry.Entity.GetType().Name
                        from ev in eve.ValidationErrors
                        select new
                               {
                                   Entity = entity,
                                   PropertyName = ev.PropertyName,
                                   ErrorMessage = ev.ErrorMessage
                               });

                    var fullErrorMessage = string.Join("; ",
                        errorMessages.Select(err => 
                            string.Format("[Entity: {0}, Property: {1}] {2}", err.Entity, err.PropertyName,
                                    err.ErrorMessage)));

                    var exceptionMessage = string.Concat(ex.Message, " The validation errors are: ", fullErrorMessage);

                    ErrorLog.GetDefault(HttpContext.Current).Log(
                        new Error(new DbEntityValidationException(exceptionMessage, dbex.EntityValidationErrors)));
                }
            }
            finally
            {
                foreach (var task in IoC.StructureMapResolver.CurrentNestedContainer.GetAllInstances<IRunOnError>())
                {
                    task.Execute();
                }

                DataContext.DisposeCurrent();
            }
        }

        public override string GetVaryByCustomString(HttpContext context, string custom)
        {
            if (custom.Contains(','))
            {
                var customStrings = custom.Split(new []{','}, StringSplitOptions.RemoveEmptyEntries);
                return string.Join(",", customStrings.Select(s => GetVaryByCustomString(context, s)));
            }
            switch (custom.ToLower())
            {
                case "lang":
                    return Thread.CurrentThread.CurrentCulture.TwoLetterISOLanguageName + '-' +
                           Thread.CurrentThread.CurrentUICulture.TwoLetterISOLanguageName;
            }


            return base.GetVaryByCustomString(context, custom);
        }
    }
}