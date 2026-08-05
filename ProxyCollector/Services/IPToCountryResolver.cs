using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using MaxMind.GeoIP2;
using ProxyCollector.Models;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver : IDisposable
{
    private readonly DatabaseReader? _countryReader;
    private readonly DatabaseReader? _cityReader;
    private readonly DatabaseReader? _asnReader;
    private readonly ConcurrentDictionary<string, CountryInfo> _countryCache = new();
    private readonly ConcurrentDictionary<string, CityInfo> _cityCache = new();
    private readonly ConcurrentDictionary<string, string> _orgCache = new();
    private bool _disposed;

    public IPToCountryResolver()
    {
        // City Database (Primary)
        var cityPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "GeoLite2-City.mmdb");
        if (File.Exists(cityPath))
        {
            try
            {
                _cityReader = new DatabaseReader(cityPath);
                Console.WriteLine($"[INFO] Loaded GeoLite2-City.mmdb");
            }
            catch (Exception ex) { Console.WriteLine($"[WARN] City DB load failed: {ex.Message}"); }
        }

        // Country Database (Fallback)
        var countryPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "GeoLite2-Country.mmdb");
        if (File.Exists(countryPath))
        {
            try
            {
                _countryReader = new DatabaseReader(countryPath);
                Console.WriteLine($"[INFO] Loaded GeoLite2-Country.mmdb");
            }
            catch (Exception ex) { Console.WriteLine($"[WARN] Country DB load failed: {ex.Message}"); }
        }

        // ASN Database (Optional — org/hosting-provider name, used when city data is missing.
        // Most proxy IPs are VPS/hosting-provider IPs, which GeoLite2-City frequently has no
        // city entry for at all — the org name is often the only extra info available for them.)
        var asnPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "GeoLite2-ASN.mmdb");
        if (File.Exists(asnPath))
        {
            try
            {
                _asnReader = new DatabaseReader(asnPath);
                Console.WriteLine($"[INFO] Loaded GeoLite2-ASN.mmdb");
            }
            catch (Exception ex) { Console.WriteLine($"[WARN] ASN DB load failed: {ex.Message}"); }
        }
    }

    public async Task<CityInfo> GetCityAsync(string address)
    {
        if (_cityReader == null)
            return await GetCountryFallbackAsync(address);

        if (_cityCache.TryGetValue(address, out var cached))
            return cached;

        try
        {
            var ip = await ResolveIpAsync(address);
            if (ip == null)
            {
                var fb = await GetCountryFallbackAsync(address);
                _cityCache[address] = fb; // negative-cache so we don't re-resolve DNS every call
                return fb;
            }

            var response = _cityReader.City(ip);
            var cityInfo = new CityInfo
            {
                CountryCode = response.Country.IsoCode ?? "XX",
                CountryName = response.Country.Name ?? "Unknown",
                CityName = response.City.Name ?? ""
            };

            _cityCache[address] = cityInfo;
            _cityCache[ip.ToString()] = cityInfo;
            return cityInfo;
        }
        catch
        {
            var fb = await GetCountryFallbackAsync(address);
            _cityCache[address] = fb;
            return fb;
        }
    }

    public async Task<CountryInfo> GetCountryAsync(string address)
    {
        if (_countryReader == null)
            return new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };

        if (_countryCache.TryGetValue(address, out var cached))
            return cached;

        try
        {
            var ip = await ResolveIpAsync(address);
            if (ip == null)
            {
                var xx = new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };
                _countryCache[address] = xx;
                return xx;
            }

            var response = _countryReader.Country(ip);
            var info = new CountryInfo
            {
                CountryCode = response.Country.IsoCode ?? "XX",
                CountryName = response.Country.Name ?? "Unknown"
            };

            _countryCache[address] = info;
            _countryCache[ip.ToString()] = info;
            return info;
        }
        catch
        {
            var xx = new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };
            _countryCache[address] = xx;
            return xx;
        }
    }

    public async Task<string?> GetOrgAsync(string address)
    {
        if (_asnReader == null) return null;

        if (_orgCache.TryGetValue(address, out var cached))
            return string.IsNullOrEmpty(cached) ? null : cached;

        try
        {
            var ip = await ResolveIpAsync(address);
            if (ip == null) { _orgCache[address] = ""; return null; }

            var response = _asnReader.Asn(ip);
            string org = response.AutonomousSystemOrganization ?? "";
            _orgCache[address] = org;
            _orgCache[ip.ToString()] = org;
            return string.IsNullOrEmpty(org) ? null : org;
        }
        catch
        {
            _orgCache[address] = "";
            return null;
        }
    }

    private async Task<CityInfo> GetCountryFallbackAsync(string address)
    {
        var country = await GetCountryAsync(address);
        return new CityInfo
        {
            CountryCode = country.CountryCode,
            CountryName = country.CountryName,
            CityName = ""
        };
    }

    // DNS.GetHostAddresses (sync) has no timeout and can block for a long time on a
    // hostname that doesn't resolve — the OS resolver's own default can run well past
    // what's reasonable here, and with hundreds of dead hostnames in a batch those
    // stalls add up to minutes of dead time. Bound every lookup to a hard 3s.
    private static readonly TimeSpan DnsTimeout = TimeSpan.FromSeconds(3);

    private static async Task<IPAddress?> ResolveIpAsync(string address)
    {
        if (IPAddress.TryParse(address, out var ip)) return ip;

        try
        {
            var dnsTask = Dns.GetHostAddressesAsync(address);
            var winner = await Task.WhenAny(dnsTask, Task.Delay(DnsTimeout));
            if (winner != dnsTask) return null; // timed out

            var addresses = await dnsTask;
            return addresses.Length > 0 ? addresses[0] : null;
        }
        catch
        {
            return null;
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _cityReader?.Dispose();
            _countryReader?.Dispose();
            _asnReader?.Dispose();
            _disposed = true;
        }
    }
}
