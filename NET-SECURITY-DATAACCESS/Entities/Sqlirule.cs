using System;
using System.Collections.Generic;

namespace NET_SECURITY_DATAACCESS.Entities;

public partial class Sqlirule
{
    public int Id { get; set; }

    public string? Pattern { get; set; }

    public string? Message { get; set; }

    public string? Ignore { get; set; }
}
