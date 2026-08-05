using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using ProxyCollector.Configuration;
using ProxyCollector.Services;

namespace ProxyCollector.Collector
{
    public class ProxyCollector
    {
        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(40) };
        private IPToCountryResolver? _resolver;
        private IPToCountryResolver Resolver => _resolver ??= new IPToCountryResolver();

        private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)
        {
            "vmess", "vless", "trojan", "ss", "shadowsocks",
            "hysteria", "hysteria2", "hy2", "tuic", "socks5", "socks"
        };

        // ====================== CLOUDFLARE / CDN CIDR FILTER ======================
        // (String-prefix matching used to live here, e.g. "104.16." — but that also
        //  matches 104.160.x.x-104.169.x.x, which is NOT Cloudflare. That false-positive
        //  was quietly dropping a lot of legitimate nodes. Precise CIDR matching below
        //  is now the only IP-range based filter.)
        private static readonly HashSet<string> CdnIpExact = new()
        {
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
        };

        private static readonly HashSet<string> SuspiciousHostSuffixes = new(StringComparer.OrdinalIgnoreCase)
        {
            "workers.dev", "pages.dev", "trycloudflare.com",
            "ngrok.io", "ngrok-free.app", "loca.lt", "serveo.net",
            "cloudflare.com", "cloudflare.net",
        };

        private static readonly (uint Network, uint Mask)[] CloudflareCidrs =
        {
            (IpToUint("103.21.244.0"),  CidrMask(22)),
            (IpToUint("103.22.200.0"),  CidrMask(22)),
            (IpToUint("103.31.4.0"),    CidrMask(22)),
            (IpToUint("141.101.64.0"),  CidrMask(18)),
            (IpToUint("108.162.192.0"), CidrMask(18)),
            (IpToUint("190.93.240.0"),  CidrMask(20)),
            (IpToUint("188.114.96.0"),  CidrMask(20)),
            (IpToUint("197.234.240.0"), CidrMask(22)),
            (IpToUint("198.41.128.0"),  CidrMask(17)),
            (IpToUint("162.158.0.0"),   CidrMask(15)),
            (IpToUint("104.16.0.0"),    CidrMask(13)),
            (IpToUint("104.24.0.0"),    CidrMask(14)),
            (IpToUint("172.64.0.0"),    CidrMask(13)),
            (IpToUint("131.0.72.0"),    CidrMask(22)),
        };

        private static uint IpToUint(string ip)
        {
            var b = IPAddress.Parse(ip).GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        private static uint CidrMask(int bits) => bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);

        private static bool IsCloudflareIp(string ipStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) return false;
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
            var b = ip.GetAddressBytes();
            uint addr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
            foreach (var (net, mask) in CloudflareCidrs)
                if ((addr & mask) == net) return true;
            return false;
        }

        private static readonly Dictionary<string, string> Flags = new(StringComparer.OrdinalIgnoreCase)
        {
            {"AD","🇦🇩"},{"AE","🇦🇪"},{"AF","🇦🇫"},{"AG","🇦🇬"},{"AI","🇦🇮"},{"AL","🇦🇱"},{"AM","🇦🇲"},
            {"AO","🇦🇴"},{"AQ","🇦🇶"},{"AR","🇦🇷"},{"AS","🇦🇸"},{"AT","🇦🇹"},{"AU","🇦🇺"},{"AW","🇦🇼"},
            {"AX","🇦🇽"},{"AZ","🇦🇿"},{"BA","🇧🇦"},{"BB","🇧🇧"},{"BD","🇧🇩"},{"BE","🇧🇪"},{"BF","🇧🇫"},
            {"BG","🇧🇬"},{"BH","🇧🇭"},{"BI","🇧🇮"},{"BJ","🇧🇯"},{"BL","🇧🇱"},{"BM","🇧🇲"},{"BN","🇧🇳"},
            {"BO","🇧🇴"},{"BQ","🇧🇶"},{"BR","🇧🇷"},{"BS","🇧🇸"},{"BT","🇧🇹"},{"BV","🇧🇻"},{"BW","🇧🇼"},
            {"BY","🇧🇾"},{"BZ","🇧🇿"},{"CA","🇨🇦"},{"CC","🇨🇨"},{"CD","🇨🇩"},{"CF","🇨🇫"},{"CG","🇨🇬"},
            {"CH","🇨🇭"},{"CI","🇨🇮"},{"CK","🇨🇰"},{"CL","🇨🇱"},{"CM","🇨🇲"},{"CN","🇨🇳"},{"CO","🇨🇴"},
            {"CR","🇨🇷"},{"CU","🇨🇺"},{"CV","🇨🇻"},{"CW","🇨🇼"},{"CX","🇨🇽"},{"CY","🇨🇾"},{"CZ","🇨🇿"},
            {"DE","🇩🇪"},{"DJ","🇩🇯"},{"DK","🇩🇰"},{"DM","🇩🇲"},{"DO","🇩🇴"},{"DZ","🇩🇿"},{"EC","🇪🇨"},
            {"EE","🇪🇪"},{"EG","🇪🇬"},{"EH","🇪🇭"},{"ER","🇪🇷"},{"ES","🇪🇸"},{"ET","🇪🇹"},{"FI","🇫🇮"},
            {"FJ","🇫🇯"},{"FK","🇫🇰"},{"FM","🇫🇲"},{"FO","🇫🇴"},{"FR","🇫🇷"},{"GA","🇬🇦"},{"GB","🇬🇧"},
            {"GD","🇬🇩"},{"GE","🇬🇪"},{"GF","🇬🇫"},{"GG","🇬🇬"},{"GH","🇬🇭"},{"GI","🇬🇮"},{"GL","🇬🇱"},
            {"GM","🇬🇲"},{"GN","🇬🇳"},{"GP","🇬🇵"},{"GQ","🇬🇶"},{"GR","🇬🇷"},{"GS","🇬🇸"},{"GT","🇬🇹"},
            {"GU","🇬🇺"},{"GW","🇬🇼"},{"GY","🇬🇾"},{"HK","🇭🇰"},{"HM","🇭🇲"},{"HN","🇭🇳"},{"HR","🇭🇷"},
            {"HT","🇭🇹"},{"HU","🇭🇺"},{"ID","🇮🇩"},{"IE","🇮🇪"},{"IL","🇮🇱"},{"IM","🇮🇲"},{"IN","🇮🇳"},
            {"IO","🇮🇴"},{"IQ","🇮🇶"},{"IR","🇮🇷"},{"IS","🇮🇸"},{"IT","🇮🇹"},{"JE","🇯🇪"},{"JM","🇯🇲"},
            {"JO","🇯🇴"},{"JP","🇯🇵"},{"KE","🇰🇪"},{"KG","🇰🇬"},{"KH","🇰🇭"},{"KI","🇰🇮"},{"KM","🇰🇲"},
            {"KN","🇰🇳"},{"KP","🇰🇵"},{"KR","🇰🇷"},{"KW","🇰🇼"},{"KY","🇰🇾"},{"KZ","🇰🇿"},{"LA","🇱🇦"},
            {"LB","🇱🇧"},{"LC","🇱🇨"},{"LI","🇱🇮"},{"LK","🇱🇰"},{"LR","🇱🇷"},{"LS","🇱🇸"},{"LT","🇱🇹"},
            {"LU","🇱🇺"},{"LV","🇱🇻"},{"LY","🇱🇾"},{"MA","🇲🇦"},{"MC","🇲🇨"},{"MD","🇲🇩"},{"ME","🇲🇪"},
            {"MF","🇲🇫"},{"MG","🇲🇬"},{"MH","🇲🇭"},{"MK","🇲🇰"},{"ML","🇲🇱"},{"MM","🇲🇲"},{"MN","🇲🇳"},
            {"MO","🇲🇴"},{"MP","🇲🇵"},{"MQ","🇲🇶"},{"MR","🇲🇷"},{"MS","🇲🇸"},{"MT","🇲🇹"},{"MU","🇲🇺"},
            {"MV","🇲🇻"},{"MW","🇲🇼"},{"MX","🇲🇽"},{"MY","🇲🇾"},{"MZ","🇲🇿"},{"NA","🇳🇦"},{"NC","🇳🇨"},
            {"NE","🇳🇪"},{"NF","🇳🇫"},{"NG","🇳🇬"},{"NI","🇳🇮"},{"NL","🇳🇱"},{"NO","🇳🇴"},{"NP","🇳🇵"},
            {"NR","🇳🇷"},{"NU","🇳🇺"},{"NZ","🇳🇿"},{"OM","🇴🇲"},{"PA","🇵🇦"},{"PE","🇵🇪"},{"PF","🇵🇫"},
            {"PG","🇵🇬"},{"PH","🇵🇭"},{"PK","🇵🇰"},{"PL","🇵🇱"},{"PM","🇵🇲"},{"PN","🇵🇳"},{"PR","🇵🇷"},
            {"PS","🇵🇸"},{"PT","🇵🇹"},{"PW","🇵🇼"},{"PY","🇵🇾"},{"QA","🇶🇦"},{"RE","🇷🇪"},{"RO","🇷🇴"},
            {"RS","🇷🇸"},{"RU","🇷🇺"},{"RW","🇷🇼"},{"SA","🇸🇦"},{"SB","🇸🇧"},{"SC","🇸🇨"},{"SD","🇸🇩"},
            {"SE","🇸🇪"},{"SG","🇸🇬"},{"SH","🇸🇭"},{"SI","🇸🇮"},{"SJ","🇸🇯"},{"SK","🇸🇰"},{"SL","🇸🇱"},
            {"SM","🇸🇲"},{"SN","🇸🇳"},{"SO","🇸🇴"},{"SR","🇸🇷"},{"SS","🇸🇸"},{"ST","🇸🇹"},{"SV","🇸🇻"},
            {"SX","🇸🇽"},{"SY","🇸🇾"},{"SZ","🇸🇿"},{"TC","🇹🇨"},{"TD","🇹🇩"},{"TF","🇹🇫"},{"TG","🇹🇬"},
            {"TH","🇹🇭"},{"TJ","🇹🇯"},{"TK","🇹🇰"},{"TL","🇹🇱"},{"TM","🇹🇲"},{"TN","🇹🇳"},{"TO","🇹🇴"},
            {"TR","🇹🇷"},{"TT","🇹🇹"},{"TV","🇹🇻"},{"TW","🇹🇼"},{"TZ","🇹🇿"},{"UA","🇺🇦"},{"UG","🇺🇬"},
            {"UM","🇺🇲"},{"US","🇺🇸"},{"UY","🇺🇾"},{"UZ","🇺🇿"},{"VA","🇻🇦"},{"VC","🇻🇨"},{"VE","🇻🇪"},
            {"VG","🇻🇬"},{"VI","🇻🇮"},{"VN","🇻🇳"},{"VU","🇻🇺"},{"WF","🇼🇫"},{"WS","🇼🇸"},{"YE","🇾🇪"},
            {"YT","🇾🇹"},{"ZA","🇿🇦"},{"ZM","🇿🇲"},{"ZW","🇿🇼"}
        };

        private static readonly Dictionary<string, string> CountryToContinent = new(StringComparer.OrdinalIgnoreCase)
        {
            {"AD","Europe"},{"AL","Europe"},{"AM","Europe"},{"AT","Europe"},{"AZ","Europe"},
            {"BA","Europe"},{"BE","Europe"},{"BG","Europe"},{"BY","Europe"},{"CH","Europe"},
            {"CY","Europe"},{"CZ","Europe"},{"DE","Europe"},{"DK","Europe"},{"EE","Europe"},
            {"ES","Europe"},{"FI","Europe"},{"FR","Europe"},{"GB","Europe"},{"GE","Europe"},
            {"GG","Europe"},{"GI","Europe"},{"GR","Europe"},{"HR","Europe"},{"HU","Europe"},
            {"IE","Europe"},{"IM","Europe"},{"IS","Europe"},{"IT","Europe"},{"JE","Europe"},
            {"LI","Europe"},{"LT","Europe"},{"LU","Europe"},{"LV","Europe"},{"MC","Europe"},
            {"MD","Europe"},{"ME","Europe"},{"MK","Europe"},{"MT","Europe"},{"NL","Europe"},
            {"NO","Europe"},{"PL","Europe"},{"PT","Europe"},{"RO","Europe"},{"RS","Europe"},
            {"RU","Europe"},{"SE","Europe"},{"SI","Europe"},{"SK","Europe"},{"SM","Europe"},
            {"TR","Europe"},{"UA","Europe"},{"VA","Europe"},{"XK","Europe"},
            {"AE","Asia"},{"AF","Asia"},{"BD","Asia"},{"BH","Asia"},{"BN","Asia"},
            {"BT","Asia"},{"CN","Asia"},{"HK","Asia"},{"ID","Asia"},{"IL","Asia"},
            {"IN","Asia"},{"IQ","Asia"},{"IR","Asia"},{"JO","Asia"},{"JP","Asia"},
            {"KG","Asia"},{"KH","Asia"},{"KP","Asia"},{"KR","Asia"},{"KW","Asia"},
            {"KZ","Asia"},{"LA","Asia"},{"LB","Asia"},{"LK","Asia"},{"MM","Asia"},
            {"MN","Asia"},{"MO","Asia"},{"MV","Asia"},{"MY","Asia"},{"NP","Asia"},
            {"OM","Asia"},{"PH","Asia"},{"PK","Asia"},{"PS","Asia"},{"QA","Asia"},
            {"SA","Asia"},{"SG","Asia"},{"SY","Asia"},{"TH","Asia"},{"TJ","Asia"},
            {"TL","Asia"},{"TM","Asia"},{"TW","Asia"},{"UZ","Asia"},{"VN","Asia"},{"YE","Asia"},
            {"AG","NorthAmerica"},{"AI","NorthAmerica"},{"AW","NorthAmerica"},{"BB","NorthAmerica"},
            {"BL","NorthAmerica"},{"BM","NorthAmerica"},{"BS","NorthAmerica"},{"BZ","NorthAmerica"},
            {"CA","NorthAmerica"},{"CR","NorthAmerica"},{"CU","NorthAmerica"},{"CW","NorthAmerica"},
            {"DM","NorthAmerica"},{"DO","NorthAmerica"},{"GD","NorthAmerica"},{"GL","NorthAmerica"},
            {"GP","NorthAmerica"},{"GT","NorthAmerica"},{"HN","NorthAmerica"},{"HT","NorthAmerica"},
            {"JM","NorthAmerica"},{"KN","NorthAmerica"},{"KY","NorthAmerica"},{"LC","NorthAmerica"},
            {"MF","NorthAmerica"},{"MQ","NorthAmerica"},{"MS","NorthAmerica"},{"MX","NorthAmerica"},
            {"NI","NorthAmerica"},{"PA","NorthAmerica"},{"PM","NorthAmerica"},{"PR","NorthAmerica"},
            {"SV","NorthAmerica"},{"TC","NorthAmerica"},{"TT","NorthAmerica"},{"US","NorthAmerica"},
            {"VC","NorthAmerica"},{"VG","NorthAmerica"},{"VI","NorthAmerica"},
            {"AR","SouthAmerica"},{"BO","SouthAmerica"},{"BR","SouthAmerica"},{"CL","SouthAmerica"},
            {"CO","SouthAmerica"},{"EC","SouthAmerica"},{"FK","SouthAmerica"},{"GF","SouthAmerica"},
            {"GY","SouthAmerica"},{"PE","SouthAmerica"},{"PY","SouthAmerica"},{"SR","SouthAmerica"},
            {"UY","SouthAmerica"},{"VE","SouthAmerica"},
            {"AO","Africa"},{"BF","Africa"},{"BI","Africa"},{"BJ","Africa"},{"BW","Africa"},
            {"CD","Africa"},{"CF","Africa"},{"CG","Africa"},{"CI","Africa"},{"CM","Africa"},
            {"CV","Africa"},{"DJ","Africa"},{"DZ","Africa"},{"EG","Africa"},{"EH","Africa"},
            {"ER","Africa"},{"ET","Africa"},{"GA","Africa"},{"GH","Africa"},{"GM","Africa"},
            {"GN","Africa"},{"GQ","Africa"},{"GW","Africa"},{"KE","Africa"},{"KM","Africa"},
            {"LR","Africa"},{"LS","Africa"},{"LY","Africa"},{"MA","Africa"},{"MG","Africa"},
            {"ML","Africa"},{"MR","Africa"},{"MU","Africa"},{"MW","Africa"},{"MZ","Africa"},
            {"NA","Africa"},{"NE","Africa"},{"NG","Africa"},{"RE","Africa"},{"RW","Africa"},
            {"SC","Africa"},{"SD","Africa"},{"SL","Africa"},{"SN","Africa"},{"SO","Africa"},
            {"SS","Africa"},{"ST","Africa"},{"SZ","Africa"},{"TD","Africa"},{"TG","Africa"},
            {"TN","Africa"},{"TZ","Africa"},{"UG","Africa"},{"YT","Africa"},{"ZA","Africa"},
            {"ZM","Africa"},{"ZW","Africa"},
            {"AU","Oceania"},{"CK","Oceania"},{"FJ","Oceania"},{"FM","Oceania"},{"GU","Oceania"},
            {"KI","Oceania"},{"MH","Oceania"},{"MP","Oceania"},{"NC","Oceania"},{"NF","Oceania"},
            {"NR","Oceania"},{"NU","Oceania"},{"NZ","Oceania"},{"PF","Oceania"},{"PG","Oceania"},
            {"PW","Oceania"},{"SB","Oceania"},{"TK","Oceania"},{"TO","Oceania"},{"TV","Oceania"},
            {"VU","Oceania"},{"WF","Oceania"},{"WS","Oceania"},
        };

        // ====================== LOGGING ======================
        private static void Log(string msg, ConsoleColor color = ConsoleColor.White)
        { Console.ForegroundColor = color; Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {msg}"); Console.ResetColor(); }
        private static void LogSuccess(string msg) => Log("✅ " + msg, ConsoleColor.Green);
        private static void LogError(string msg)   => Log("❌ " + msg, ConsoleColor.Red);
        private static void LogInfo(string msg)    => Log("ℹ️  " + msg, ConsoleColor.Cyan);
        private static void LogWarning(string msg) => Log("⚠️  " + msg, ConsoleColor.Yellow);

        // ====================== GEOIP DOWNLOAD ======================
        private static async Task DownloadGeoIPDatabases(HttpClient http)
        {
            LogInfo("Downloading GeoLite2-City.mmdb...");
            foreach (var url in new[]
            {
                "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
                "https://github.com/alecthw/mmdb_china_ip_list/raw/release/lite/GeoLite2-City.mmdb"
            })
            {
                try
                {
                    var resp = await http.GetAsync(url);
                    resp.EnsureSuccessStatusCode();
                    await using var fs = new FileStream("ProxyCollector/GeoLite2-City.mmdb", FileMode.Create);
                    await resp.Content.CopyToAsync(fs);
                    LogSuccess("GeoLite2-City.mmdb downloaded."); break;
                }
                catch (Exception ex) { LogWarning($"City DB failed: {ex.Message}"); }
            }

            LogInfo("Downloading GeoLite2-Country.mmdb...");
            foreach (var url in new[]
            {
                "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
                "https://git.io/GeoLite2-Country.mmdb"
            })
            {
                try
                {
                    var resp = await http.GetAsync(url);
                    resp.EnsureSuccessStatusCode();
                    await using var fs = new FileStream("ProxyCollector/GeoLite2-Country.mmdb", FileMode.Create);
                    await resp.Content.CopyToAsync(fs);
                    LogSuccess("GeoLite2-Country.mmdb downloaded."); break;
                }
                catch (Exception ex) { LogWarning($"Country DB failed: {ex.Message}"); }
            }
        }

        // ====================== HOST FILTERING ======================
        private static bool IsBadHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return true;
            if (CdnIpExact.Contains(host)) return true;

            foreach (var s in SuspiciousHostSuffixes)
                if (host.EndsWith(s, StringComparison.OrdinalIgnoreCase)) return true;

            if (IPAddress.TryParse(host, out _))
            {
                if (IsCloudflareIp(host)) return true;
            }

            return false;
        }

        // ====================== LOCATION ======================
        // Fallback chain: city-on-host -> country-on-host -> (if hostname) resolve DNS,
        // then city-on-resolved-ip -> country-on-resolved-ip -> Unknown.
        // Doing the city lookup on the resolved IP too (not just country, as before)
        // means hostname-based nodes get the same city-level precision as IP-based ones.
        private string GetLocation(string host)
        {
            try
            {
                string? result = TryCityThenCountry(host);
                if (result != null) return result;

                if (!IPAddress.TryParse(host, out _))
                {
                    try
                    {
                        var addrs = Dns.GetHostAddresses(host);
                        foreach (var addr in addrs)
                        {
                            result = TryCityThenCountry(addr.ToString());
                            if (result != null) return result;
                        }
                    }
                    catch { }
                }

                return "🌐 Unknown";
            }
            catch { return "🌐 Unknown"; }
        }

        private string? TryCityThenCountry(string ipOrHost)
        {
            var city = Resolver.GetCity(ipOrHost);
            if (!string.IsNullOrEmpty(city?.CityName))
            {
                string cityCc = city.CountryCode?.ToUpper() ?? "";
                string flag = Flags.TryGetValue(cityCc, out var f) ? f : "🌍";
                string cityName = System.Globalization.CultureInfo.InvariantCulture.TextInfo
                    .ToTitleCase(city.CityName.Trim().ToLowerInvariant());
                return $"{flag} {cityName}, {cityCc}";
            }

            var country = Resolver.GetCountry(ipOrHost);
            string cc = country?.CountryCode?.ToUpper() ?? "";
            if (!string.IsNullOrEmpty(cc) && cc != "XX")
            {
                string flagC = Flags.TryGetValue(cc, out var fc) ? fc : "🌍";
                string name = !string.IsNullOrEmpty(country?.CountryName) && country.CountryName != "Unknown"
                    ? country.CountryName : cc;
                return $"{flagC} {name}";
            }

            return null;
        }

        private static string GetContinent(string cc)
            => CountryToContinent.TryGetValue(cc ?? "", out var c) ? c : "Unknown";

        // ====================== QUALITY SCORING ======================
        private static int ComputeQualityScore(ParsedProxy p)
        {
            int score = 0;
            string proto = NormalizeProto(p.Protocol);

            score += proto switch
            {
                "hysteria2" => 100,
                "tuic"      => 90,
                "vless"     => 80,
                "trojan"    => 70,
                "vmess"     => 50,
                "ss"        => 40,
                _           => 10
            };

            string sec = p.Security.ToLowerInvariant();
            if (sec == "reality")          score += 30;
            else if (sec == "tls")         score += 20;
            else if (sec is "none" or "") score -= 10;

            // Penalize TLS protocol on non-TLS port
            if (sec == "tls" && int.TryParse(p.Port, out int portCheck) && portCheck == 80)
                score -= 15;

            string net = p.Network.ToLowerInvariant();
            score += net switch
            {
                "xhttp"       => 12,
                "httpupgrade" => 10,
                "grpc"        => 10,
                "ws"          => 8,
                "h2"          => 8,
                _             => 0
            };

            if (!string.IsNullOrEmpty(p.Sni)) score += 10;

            if (Regex.IsMatch(p.Credential,
                @"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                RegexOptions.IgnoreCase))
                score += 15;

            if (int.TryParse(p.Port, out int pt))
                score += pt switch
                {
                    443 or 8443 or 2053 or 2083 or 2087 or 2096 => 15,
                    80 or 8080 or 8880 or 2052 or 2082 or 2086  => 8,
                    _ => 0
                };

            return score;
        }

        // ====================== ENTRY POINT ======================
        public async Task StartAsync()
        {
            await DownloadGeoIPDatabases(_http);
            LogSuccess("🚀 FastNodes v5.7 - Starting collection...");
            await RunFullCollectionMode();
        }

        // ====================== MAIN PIPELINE ======================
        private async Task RunFullCollectionMode()
        {
            var urls = CollectorConfig.Instance.Sources;
            LogInfo($"🔍 Fetching from {urls.Length} sources (parallel)...");

            // STEP 1: parallel fetch
            var rawLinesBag = new ConcurrentBag<string>();
            await Parallel.ForEachAsync(urls, new ParallelOptions { MaxDegreeOfParallelism = 30 },
                async (url, _) =>
                {
                    try
                    {
                        var text = await _http.GetStringAsync(url);
                        foreach (var l in DecodeAndExtractLines(text, url)) rawLinesBag.Add(l);
                    }
                    catch (Exception ex) { LogError($"Failed {url}: {ex.Message}"); }
                });

            var rawLines = rawLinesBag.ToList();
            LogInfo($"Total raw lines: {rawLines.Count}");

            // STEP 2: parse + smart dedup + quality score
            LogInfo("🧹 Parsing, smart dedup, quality scoring...");
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var uniqueProxies = new List<ParsedProxy>();
            int processed = 0, cfFiltered = 0;

            foreach (var line in rawLines)
            {
                processed++;
                if (processed % 100000 == 0) LogInfo($"  {processed}/{rawLines.Count} parsed...");

                var t = line.Trim();
                if (string.IsNullOrWhiteSpace(t) || t.StartsWith("#")) continue;
                if (Regex.IsMatch(t, @"^\s*-\s+name:")) continue;

                var p = ParseProxyLine(t);
                if (p == null) continue;
                if (p.Host is "0.0.0.0" or "127.0.0.1" or "localhost") continue;

                if (IsBadHost(p.Host)) { cfFiltered++; continue; }

                if (seen.Add(p.DeduplicationKey))
                {
                    p.QualityScore = ComputeQualityScore(p);
                    uniqueProxies.Add(p);
                }
            }

            LogInfo($"After smart dedup: {uniqueProxies.Count} unique ({cfFiltered} CDN filtered)");

            // STEP 3: TCP alive check — two passes.
            // Pass 1 finds candidates (same as before). Pass 2 re-probes only the survivors
            // to confirm they're actually stable (not a one-off successful handshake) and
            // gives an averaged, more trustworthy latency. Only re-probing the smaller
            // survivor set keeps this cheap relative to pass 1.
            LogInfo("🔌 TCP alive check — pass 1 (parallel)...");
            var firstPassBag = new ConcurrentBag<(ParsedProxy Proxy, int Latency)>();

            await Parallel.ForEachAsync(uniqueProxies, new ParallelOptions { MaxDegreeOfParallelism = 200 },
                async (p, _) =>
                {
                    int lat = await TcpProbe(p.Host, p.Port);
                    if (lat >= 0) firstPassBag.Add((p, lat));
                });

            var firstPass = firstPassBag.ToList();
            LogSuccess($"Pass 1 alive: {firstPass.Count}");

            LogInfo("🔌 TCP alive check — pass 2 (confirming stability)...");
            var confirmedBag = new ConcurrentBag<(ParsedProxy Proxy, int Latency, bool Stable)>();

            await Parallel.ForEachAsync(firstPass, new ParallelOptions { MaxDegreeOfParallelism = 200 },
                async (item, _) =>
                {
                    int lat2 = await TcpProbe(item.Proxy.Host, item.Proxy.Port);
                    if (lat2 >= 0)
                        confirmedBag.Add((item.Proxy, (item.Latency + lat2) / 2, true));
                    else
                        confirmedBag.Add((item.Proxy, item.Latency, false)); // passed once, not stable — kept but ranked lower
                });

            // Real-performance ranking: stable nodes first, then fastest measured latency.
            // QualityScore (protocol/TLS/port heuristics) is now only the final tiebreaker,
            // so top1000 reflects nodes that actually connect fast and reliably.
            var alive = confirmedBag
                .OrderByDescending(x => x.Stable)
                .ThenBy(x => x.Latency)
                .ThenByDescending(x => x.Proxy.QualityScore)
                .Select(x => (x.Proxy, x.Latency))
                .ToList();

            LogSuccess($"Alive proxies: {alive.Count} ({confirmedBag.Count(x => x.Stable)} stable)");

            // STEP 4: GeoIP warm + stable single-pass rename
            LogInfo("🌍 GeoIP lookup + rename...");
            _ = Resolver;

            var uniqueHosts = alive.Select(x => x.Proxy.Host).Distinct().ToList();
            LogInfo($"  Warming GeoIP cache for {uniqueHosts.Count} unique hosts...");
            await Parallel.ForEachAsync(uniqueHosts, new ParallelOptions { MaxDegreeOfParallelism = 50 },
                (host, _) => { try { GetLocation(host); } catch { } return ValueTask.CompletedTask; });

            // ROOT-CAUSE FIX: cache location per host ONCE after warm-up.
            // GetLocation() calls DNS which is non-deterministic between invocations —
            // the same host can resolve to a different string on a second call if DNS
            // times out or the GeoIP cache hits differently. Calling it in both Pass 1
            // and Pass 2 meant the baseRemark key could differ, causing KeyNotFoundException.
            // Now we call it exactly once per host and reuse the frozen result everywhere.
            var locationCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var host in uniqueHosts)
            {
                try { locationCache[host] = GetLocation(host); }
                catch { locationCache[host] = "🌐 Unknown"; }
            }
            string Loc(string h) => locationCache.TryGetValue(h, out var l) ? l : "🌐 Unknown";

            var finalProxies = new List<FinalProxy>();

            // Pass 1: count total occurrences of each base remark using frozen locations
            // NOTE: remark no longer contains the server address/port — just geo + protocol —
            // so uniqueness is purely location+protocol based now.
            var remarkTotal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in alive)
            {
                var p = item.Proxy;
                string baseRemark = $"{Loc(p.Host)} | {NormalizeProto(p.Protocol).ToUpperInvariant()}";
                remarkTotal.TryGetValue(baseRemark, out int cnt);
                remarkTotal[baseRemark] = cnt + 1;
            }

            // Pass 2: assign remarks — unique nodes get no suffix, duplicates get #1, #2, #3...
            var remarkCounter = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in alive)
            {
                var p = item.Proxy;
                string proto = NormalizeProto(p.Protocol);
                string baseRemark = $"{Loc(p.Host)} | {proto.ToUpperInvariant()}";

                remarkCounter.TryGetValue(baseRemark, out int current);
                remarkCounter[baseRemark] = current + 1;

                // Safe — guaranteed to exist because same frozen Loc() used in both passes
                remarkTotal.TryGetValue(baseRemark, out int total);

                string remark = total <= 1
                    ? baseRemark
                    : $"{baseRemark} #{current + 1}";

                string cleanLink = BuildCleanLink(p, remark);
                string cc = Resolver.GetCountry(p.Host)?.CountryCode?.ToUpper() ?? "XX";
                string continent = GetContinent(cc);

                finalProxies.Add(new FinalProxy
                {
                    Link = cleanLink, Proto = proto, CountryCode = cc,
                    Continent = continent, Remark = remark,
                    Latency = item.Latency, QualityScore = p.QualityScore
                });
            }

            await SaveAllCategories(finalProxies);
            LogSuccess("🎉 Done!");
        }

        // ====================== TCP PROBE ======================
        private static async Task<int> TcpProbe(string host, string port)
        {
            if (!int.TryParse(port, out int portNum) || portNum <= 0 || portNum > 65535) return -1;
            try
            {
                using var cts = new CancellationTokenSource(3500);
                using var tcp = new TcpClient();
                var sw = Stopwatch.StartNew();
                await tcp.ConnectAsync(host, portNum, cts.Token);
                sw.Stop();
                return (int)sw.ElapsedMilliseconds;
            }
            catch { return -1; }
        }

        // ====================== BUILD CLEAN LINK ======================
        private static string BuildCleanLink(ParsedProxy p, string remark)
        {
            string encoded = Uri.EscapeDataString(remark);
            try
            {
                if (NormalizeProto(p.Protocol) == "vmess")
                {
                    var obj = new Dictionary<string, object?>
                    {
                        ["v"] = "2", ["ps"] = remark, ["add"] = p.Host, ["port"] = p.Port,
                        ["id"] = p.Credential, ["aid"] = p.Aid,
                        ["net"] = string.IsNullOrEmpty(p.Network) ? "tcp" : p.Network,
                        ["type"] = "none", ["host"] = p.Sni, ["path"] = p.Path,
                        ["tls"] = p.Security == "tls" ? "tls" : ""
                    };
                    string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(obj)));
                    return $"vmess://{b64}";
                }
            }
            catch { }
            return p.BaseLink.TrimEnd() + "#" + encoded;
        }

        // ====================== SOURCE DECODING ======================
        private static List<string> DecodeAndExtractLines(string text, string url)
        {
            var results = new List<string>();
            bool isYaml = url.EndsWith(".yaml") || url.EndsWith(".yml");
            bool isHtml = url.EndsWith(".html") || url.EndsWith(".htm");

            if (isHtml)
            {
                foreach (Match m in Regex.Matches(text,
                    @"(vless|vmess|trojan|ss|hysteria2?|hy2|tuic|socks5?)://[^\s""'<>\[\]]+",
                    RegexOptions.IgnoreCase))
                    results.Add(m.Value);
                return results;
            }

            if (isYaml || text.Contains("proxies:"))
            {
                foreach (var line in text.Split('\n', '\r'))
                {
                    var t = line.Trim();
                    if (t.Contains("://") && !t.StartsWith("#")) results.Add(t);
                }
                return results;
            }

            if (!text.Contains("://"))
            {
                try
                {
                    string trim = text.Trim();
                    int pad = trim.Length % 4; if (pad > 0) trim += new string('=', 4 - pad);
                    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(trim));
                    if (decoded.Contains("://")) text = decoded;
                }
                catch { }
            }

            foreach (var rawLine in text.Split('\n', '\r'))
            {
                var t = rawLine.Trim();
                if (string.IsNullOrEmpty(t) || t.StartsWith("#")) continue;

                if (t.Contains("://"))
                {
                    var m = Regex.Match(t,
                        @"(vless|vmess|trojan|ss|hysteria2?|hy2|tuic|socks5?)://\S+",
                        RegexOptions.IgnoreCase);
                    if (m.Success) results.Add(m.Value);
                    else results.Add(t);
                }
                else if (t.Length > 20)
                {
                    try
                    {
                        int pad = t.Length % 4;
                        string padded = pad > 0 ? t + new string('=', 4 - pad) : t;
                        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
                        if (decoded.Contains("://"))
                            foreach (var dl in decoded.Split('\n', '\r'))
                            {
                                var dm = Regex.Match(dl.Trim(),
                                    @"(vless|vmess|trojan|ss|hysteria2?|hy2|tuic|socks5?)://\S+",
                                    RegexOptions.IgnoreCase);
                                if (dm.Success) results.Add(dm.Value);
                            }
                    }
                    catch { }
                }
            }

            return results;
        }

        // ====================== SAVE OUTPUTS ======================
        // Raw output only (no yaml/json) — every category gets two files:
        //   <name>.txt          full list
        //   <name>.top1000.txt  best 1000 nodes (already quality+latency sorted upstream)
        private const int TopCap = 1000;

        private async Task SaveAllCategories(List<FinalProxy> proxies)
        {
            var sub = Path.Combine(Directory.GetCurrentDirectory(), "sub");
            foreach (var d in new[] { "protocols", "countries", "continents" })
                Directory.CreateDirectory(Path.Combine(sub, d));

            await WriteTxt(Path.Combine(sub, "everything"), proxies);
            LogSuccess($"Saved everything.txt / everything.top1000.txt ({proxies.Count})");

            foreach (var g in proxies.GroupBy(x => x.Proto))
            {
                string key = g.Key.Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(key) || key == "unknown") continue;

                await WriteTxt(Path.Combine(sub, "protocols", key), g.ToList());
                LogSuccess($"  → protocols/{key} ({g.Count()})");
            }

            foreach (var g in proxies.GroupBy(x => x.CountryCode))
            {
                if (string.IsNullOrEmpty(g.Key) || g.Key == "XX" || g.Count() < 3) continue;
                string safe = Regex.Replace(g.Key, @"[^A-Z0-9]", "");
                if (string.IsNullOrEmpty(safe)) continue;
                await WriteTxt(Path.Combine(sub, "countries", safe), g.ToList());
                LogSuccess($"  → countries/{safe} ({g.Count()})");
            }

            foreach (var g in proxies.GroupBy(x => x.Continent))
            {
                if (g.Key == "Unknown" || g.Count() < 3) continue;
                await WriteTxt(Path.Combine(sub, "continents", g.Key), g.ToList());
                LogSuccess($"  → continents/{g.Key} ({g.Count()})");
            }
        }

        // ====================== WRITE TXT (+ TOP1000) ======================
        private static async Task WriteTxt(string pathNoExt, List<FinalProxy> proxies)
        {
            // Full plain-text URI list
            await File.WriteAllLinesAsync(pathNoExt + ".txt", proxies.Select(x => x.Link));

            // Best 1000 only — proxies is already ordered by QualityScore desc, then latency asc
            var top = proxies.Count > TopCap ? proxies.Take(TopCap) : proxies;
            await File.WriteAllLinesAsync(pathNoExt + ".top1000.txt", top.Select(x => x.Link));
        }

        // ====================== PARSE ======================
        private static ParsedProxy? ParseProxyLine(string line)
        {
            line = line.Trim();
            if (line.Length < 10) return null;

            int hashIdx = line.IndexOf('#');
            string baseLink = hashIdx >= 0 ? line[..hashIdx].Trim() : line.Trim();
            if (string.IsNullOrEmpty(baseLink)) return null;

            if (baseLink.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string b64 = baseLink["vmess://".Length..];
                    int pad = b64.Length % 4; if (pad > 0) b64 += new string('=', 4 - pad);
                    string json = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                    using var doc = JsonDocument.Parse(json);
                    var r = doc.RootElement;

                    string host = r.TryGetProperty("add",  out var add)   ? (add.GetString()   ?? "") : "";
                    string port = r.TryGetProperty("port", out var portEl)
                        ? (portEl.ValueKind == JsonValueKind.Number ? portEl.GetInt32().ToString() : portEl.GetString() ?? "443")
                        : "443";
                    string uuid = r.TryGetProperty("id",   out var id)    ? (id.GetString()    ?? "") : "";
                    string net  = r.TryGetProperty("net",  out var netEl)  ? (netEl.GetString()  ?? "tcp") : "tcp";
                    string tls  = r.TryGetProperty("tls",  out var tlsEl)  ? (tlsEl.GetString()  ?? "") : "";
                    string sni  = r.TryGetProperty("host", out var sniEl)  ? (sniEl.GetString()  ?? "") : "";
                    string path = r.TryGetProperty("path", out var pathEl) ? (pathEl.GetString() ?? "") : "";
                    int aid     = r.TryGetProperty("aid",  out var aidEl)
                        ? (aidEl.ValueKind == JsonValueKind.Number ? aidEl.GetInt32() : 0) : 0;

                    if (string.IsNullOrEmpty(host) || host == "0.0.0.0") return null;

                    return new ParsedProxy
                    {
                        Protocol = "vmess", Host = host, Port = port,
                        Credential = uuid, Network = net, Security = tls,
                        Sni = sni, Path = path, Aid = aid, BaseLink = baseLink
                    };
                }
                catch { return null; }
            }

            try
            {
                var uri = new Uri(baseLink);
                string scheme = uri.Scheme.ToLowerInvariant();
                if (!ValidProtocols.Contains(scheme)) return null;

                string h = uri.Host;
                int p = uri.Port > 0 ? uri.Port : 443;
                if (string.IsNullOrEmpty(h) || h == "0.0.0.0") return null;

                var q = ParseQuery(uri.Query);
                string sec  = q.GetValueOrDefault("security", "");
                string net  = q.GetValueOrDefault("type", "tcp");
                string sni  = q.GetValueOrDefault("sni", "") is var s && !string.IsNullOrEmpty(s)
                              ? s : q.GetValueOrDefault("host", "");
                string path = q.GetValueOrDefault("path", "");

                return new ParsedProxy
                {
                    Protocol   = scheme,
                    Host       = h,
                    Port       = p.ToString(),
                    Credential = uri.UserInfo ?? "",
                    Network    = net,
                    Security   = sec,
                    Sni        = sni,
                    Path       = path,
                    BaseLink   = baseLink
                };
            }
            catch { return null; }
        }

        private static string NormalizeProto(string proto)
        {
            if (string.IsNullOrEmpty(proto)) return "unknown";
            proto = proto.ToLowerInvariant();
            if (proto is "hy2" || proto.StartsWith("hysteria")) return "hysteria2";
            if (proto == "shadowsocks") return "ss";
            return proto;
        }

        private static Dictionary<string, string> ParseQuery(string query)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(query)) return result;
            foreach (var pair in query.TrimStart('?').Split('&'))
            {
                var kv = pair.Split('=', 2);
                if (kv.Length == 2)
                    result[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1]);
            }
            return result;
        }
    }

    // ====================== DATA MODELS ======================
    public class ParsedProxy
    {
        public string Protocol    { get; set; } = "";
        public string Host        { get; set; } = "";
        public string Port        { get; set; } = "";
        public string Credential  { get; set; } = "";
        public string Network     { get; set; } = "tcp";
        public string Security    { get; set; } = "";
        public string Sni         { get; set; } = "";
        public string Path        { get; set; } = "";
        public int    Aid         { get; set; } = 0;
        public string BaseLink    { get; set; } = "";
        public int    QualityScore { get; set; } = 0;

        public string DeduplicationKey =>
            $"{NP(Protocol)}:{Host.ToLowerInvariant()}:{Port}:{Credential.ToLowerInvariant()}:{Network.ToLowerInvariant()}:{Security.ToLowerInvariant()}";

        private static string NP(string p)
        {
            if (string.IsNullOrEmpty(p)) return "unknown";
            p = p.ToLowerInvariant();
            if (p is "hy2" || p.StartsWith("hysteria")) return "hysteria2";
            if (p == "shadowsocks") return "ss";
            return p;
        }
    }

    public class FinalProxy
    {
        public string  Link             { get; set; } = "";
        public string  Proto            { get; set; } = "";
        public string  CountryCode      { get; set; } = "XX";
        public string  Continent        { get; set; } = "Unknown";
        public string  Remark           { get; set; } = "";
        public int     Latency          { get; set; }
        public int     QualityScore     { get; set; }
    }
}
