using System;
using System.Data.Entity;
using System.Data.Entity.ModelConfiguration.Conventions;
using System.Web;
using AspNetBase.Domain;
using Microsoft.AspNet.Identity.EntityFramework;

namespace AspNetBase.DAL
{
    public class DataContext : DbContext
    {
        public DataContext() : base("AspNetBase")
        {
        }

        public DataContext(string connectionString) : base(connectionString)
        {
            Database.Connection.ConnectionString = connectionString; 
        }

        public IDbSet<User> Users { get; set; }

        public static DataContext Current
        {
            get
            {
                if (HttpContext.Current != null && HttpContext.Current.Items["DataContext"] != null)
                    return HttpContext.Current.Items["DataContext"] as DataContext;

                DataContext entities = Create();
                if (HttpContext.Current != null)
                    HttpContext.Current.Items["DataContext"] = entities;
                return entities;
            }
        }

        public static DataContext Create()
        {
            return new DataContext();
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Conventions.Remove<OneToManyCascadeDeleteConvention>();

            modelBuilder.Entity<IdentityUserLogin>().HasKey<string>(l => l.UserId);
            modelBuilder.Entity<IdentityRole>().HasKey<string>(r => r.Id);
            modelBuilder.Entity<IdentityUserRole>().HasKey(r => new {r.RoleId, r.UserId});
        }

        public static void DisposeCurrent()
        {
            if (HttpContext.Current.Items["DataContext"] != null)
            {
                var entities = (DataContext) HttpContext.Current.Items["DataContext"];
                entities.Dispose();
            }
        }
    }
}