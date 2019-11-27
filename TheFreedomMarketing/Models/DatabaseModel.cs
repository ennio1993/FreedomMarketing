using MySql.Data.Entity;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;
using static TheFreedomMarketing.Models.DataModel;

namespace TheFreedomMarketing.Models
{
    public class DatabaseModel
    {
        [DbConfigurationType(typeof(MySqlEFConfiguration))]
        public class MySqlContext : DbContext
        {
            public MySqlContext(string connectionstring) : base(connectionstring)
            {
                this.Configuration.LazyLoadingEnabled = false;
            }
            //DbSets....
            public DbSet<Roles> Roles { get; set; }
            public DbSet<Usuarios> Usuarios { get; set; }
        }
    }
}