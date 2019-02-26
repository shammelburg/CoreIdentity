using System;
using System.ComponentModel.DataAnnotations;

namespace CoreIdentity.Data.Models
{
    public class spGetOneExample
    {
        [Key]
        public int Id { get; set; }
        public string Name { get; set; }
        public DateTime? DOB { get; set; }
        public bool Active { get; set; }
    }
}
