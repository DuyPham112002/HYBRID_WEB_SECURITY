using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace NET_SECURITY_DATAACCESS.Entities;

public partial class NetsecurityContext : DbContext
{
    public NetsecurityContext()
    {
    }

    public NetsecurityContext(DbContextOptions<NetsecurityContext> options)
        : base(options)
    {
    }

    public virtual DbSet<Sqlidefault> Sqlidefaults { get; set; }

    public virtual DbSet<Sqliescape> Sqliescapes { get; set; }

    public virtual DbSet<Sqlilogical> Sqlilogicals { get; set; }

    public virtual DbSet<Sqlirule> Sqlirules { get; set; }

    public virtual DbSet<SqliruleTarget> SqliruleTargets { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
#warning To protect potentially sensitive information in your connection string, you should move it out of source code. You can avoid scaffolding the connection string by using the Name= syntax to read it from configuration - see https://go.microsoft.com/fwlink/?linkid=2131148. For more guidance on storing connection strings, see https://go.microsoft.com/fwlink/?LinkId=723263.
        => optionsBuilder.UseSqlite("Data Source=NETSecurity.db");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Sqlidefault>(entity =>
        {
            entity.ToTable("Sqlidefault");
        });

        modelBuilder.Entity<Sqliescape>(entity =>
        {
            entity.ToTable("Sqliescape");
        });

        modelBuilder.Entity<Sqlilogical>(entity =>
        {
            entity.ToTable("Sqlilogical");
        });

        modelBuilder.Entity<Sqlirule>(entity =>
        {
            entity.ToTable("Sqlirule");

            entity.Property(e => e.Id).ValueGeneratedNever();
        });

        modelBuilder.Entity<SqliruleTarget>(entity =>
        {
            entity.ToTable("Sqlirule_Target");
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
