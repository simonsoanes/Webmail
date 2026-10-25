// Copyright 2026 Simon Soanes
// SPDX-License-Identifier: Apache-2.0

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Nullify.WebMail.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<UserPreference> UserPreferences => Set<UserPreference>();
    public DbSet<ImapFolderCache> ImapFolderCache => Set<ImapFolderCache>();
    public DbSet<SieveScript> SieveScripts => Set<SieveScript>();
    public DbSet<PgpKey> PgpKeys => Set<PgpKey>();
    public DbSet<Domain> Domains => Set<Domain>();
    public DbSet<AdminSetting> AdminSettings => Set<AdminSetting>();
    public DbSet<TrustedDevice> TrustedDevices => Set<TrustedDevice>();
    public DbSet<Passkey> Passkeys => Set<Passkey>();

    protected override void ConfigureConventions(ModelConfigurationBuilder conventions)
    {
        // Npgsql maps DateTime to timestamptz, which refuses values whose Kind isn't Utc.
        // Every timestamp here is UTC by name, so store them as such and read them back
        // with Kind=Utc. SQLite keeps its existing text mapping untouched.
        if (Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL")
            conventions.Properties<DateTime>().HaveConversion<UtcDateTimeConverter>();
    }

    private sealed class UtcDateTimeConverter() : ValueConverter<DateTime, DateTime>(
        v => v.Kind == DateTimeKind.Local ? v.ToUniversalTime() : DateTime.SpecifyKind(v, DateTimeKind.Utc),
        v => DateTime.SpecifyKind(v, DateTimeKind.Utc));

    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<User>(u =>
        {
            u.HasIndex(x => x.Username).IsUnique();
            u.HasIndex(x => x.Email);
        });

        model.Entity<UserPreference>(p =>
        {
            p.HasIndex(x => new { x.UserId, x.Key }).IsUnique();
        });

        model.Entity<ImapFolderCache>(f =>
        {
            f.HasIndex(x => new { x.UserId, x.Name }).IsUnique();
        });

        model.Entity<SieveScript>(s =>
        {
            s.HasIndex(x => new { x.UserId, x.Name }).IsUnique();
        });

        model.Entity<PgpKey>(k =>
        {
            k.HasIndex(x => new { x.UserId, x.KeyId }).IsUnique();
        });

        model.Entity<Domain>(d =>
        {
            d.HasIndex(x => x.Name).IsUnique();
        });

        model.Entity<AdminSetting>(s =>
        {
            s.HasIndex(x => x.Key).IsUnique();
        });

        model.Entity<TrustedDevice>(d =>
        {
            d.HasIndex(x => x.DeviceId).IsUnique();
            d.HasIndex(x => x.UserId);
        });

        model.Entity<Passkey>(k =>
        {
            k.HasIndex(x => x.CredentialId).IsUnique();
            k.HasIndex(x => x.UserId);
            // Two sign-ins racing with one passkey: only the first may wrap the login again.
            k.Property(x => x.WrapVersion).IsConcurrencyToken();
        });
    }
}