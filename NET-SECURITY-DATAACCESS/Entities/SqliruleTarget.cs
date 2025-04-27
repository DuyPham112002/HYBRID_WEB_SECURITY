using System;
using System.Collections.Generic;

namespace NET_SECURITY_DATAACCESS.Entities;

public partial class SqliruleTarget
{
    public int Id { get; set; }

    public string? Target { get; set; }

    public int? RuleId { get; set; }
}
