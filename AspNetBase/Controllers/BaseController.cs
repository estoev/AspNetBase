using System;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using AspNetBase.DAL;
using AspNetBase.DependencyResolution;
using AspNetBase.Helpers;

namespace AspNetBase.Controllers
{
    public class BaseController : Controller
    {
        protected readonly DataContext db;
		protected readonly ICurrentUser currentUser;

        public BaseController()
        {
        }

        public BaseController(DataContext db) : this()
        {
            this.db = db;
        }

        public BaseController(DataContext db, ICurrentUser currentUser) : this(db)
		{
			this.currentUser = currentUser;
		}

        protected override IAsyncResult BeginExecuteCore(AsyncCallback callback, object state)
        {
            return base.BeginExecuteCore(callback, state);
        }

        [Obsolete(
            "Do not use the standard Json helpers to return JSON data to the client.  Use either JsonSuccess or JsonError instead."
            )]
        protected JsonResult Json<T>(T data)
        {
            throw new InvalidOperationException(
                "Do not use the standard Json helpers to return JSON data to the client.  Use either JsonSuccess or JsonError instead.");
        }

        protected StandardJsonResult JsonValidationError()
        {
            var result = new StandardJsonResult();

            foreach (ModelError validationError in ModelState.Values.SelectMany(v => v.Errors))
            {
                result.AddError(validationError.ErrorMessage);
            }
            return result;
        }

        protected StandardJsonResult JsonError(string errorMessage)
        {
            var result = new StandardJsonResult();

            result.AddError(errorMessage);

            return result;
        }

        protected StandardJsonResult<T> JsonSuccess<T>(T data)
        {
            return new StandardJsonResult<T> {Data = data};
        }
    }
}