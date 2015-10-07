using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using AutoMapper;
using AspNetBase.Domain;

namespace AspNetBase.Models
{
    public class UserDetailsViewModel : IHaveCustomMappings
    {
        public string Id { get; set; }

        public string Name { get; set; }

        public string Email { get; set; }

        public void CreateMappings(IConfiguration configuration)
        {
            Mapper.CreateMap<User, UserDetailsViewModel>();
        }
    }
}