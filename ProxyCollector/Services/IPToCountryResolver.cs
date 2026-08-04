using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using MaxMind.GeoIP2;
using ProxyCollector.Models;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver : IDisposable
{
    private readonly DatabaseReader? _countryReader;
    private readonly DatabaseReader? _cityReader;
    private readonly ConcurrentDictionary<string, CountryInfo> _countryCache = new();
    private readonly ConcurrentDictionary<string, CityInfo> _cityCache = new();
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
    }

    public CityInfo GetCity(string address)
    {
        if (_cityReader == null)
            return GetCountryFallback(address);

        if (_cityCache.TryGetValue(address, out var cached))
            return cached;

        try
        {
            var ip = ResolveIp(address);
            if (ip == null) return GetCountryFallback(address);

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
            return GetCountryFallback(address);
        }
    }

    public CountryInfo GetCountry(string address)
    {
        if (_countryReader == null)
            return new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };

        if (_countryCache.TryGetValue(address, out var cached))
            return cached;

        try
        {
            var ip = ResolveIp(address);
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

    private CityInfo GetCountryFallback(string address)
    {
        var country = GetCountry(address);
        return new CityInfo
        {
            CountryCode = country.CountryCode,
            CountryName = country.CountryName,
            CityName = ""
        };
    }

    private IPAddress? ResolveIp(string address)
    {
        if (IPAddress.TryParse(address, out var ip)) return ip;

        try
        {
            var addresses = Dns.GetHostAddresses(address);
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
            _disposed = true;
        }
    }
}
