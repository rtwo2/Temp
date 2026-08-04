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
        private static readonly string[] CdnIpPrefixes =
        {
            "162.159.", "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
            "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.",
            "172.71.", "173.245.", "108.162.", "190.93.", "188.114.", "197.234.", "198.41.",
            "1.1.1.", "1.0.0.", "162.158.", "3.33.", "15.197.",
        };

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

        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

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

        // ====================== BLACKLIST ======================
        private static async Task DownloadFreshFireHOLBlacklist(HttpClient http)
        {
            LogInfo("Downloading FireHOL blacklist...");
            try
            {
                var resp = await http.GetAsync("https://iplists.firehol.org/files/firehol_level1.netset");
                resp.EnsureSuccessStatusCode();
                await using var fs = new FileStream("ProxyCollector/blacklist.netset", FileMode.Create);
                await resp.Content.CopyToAsync(fs);
                LogSuccess("FireHOL downloaded.");
            }
            catch (Exception ex) { LogWarning($"FireHOL failed: {ex.Message}"); }
        }

        private static void LoadAllBlacklists()
        {
            BlacklistCidrs.Clear();
            var path = "ProxyCollector/blacklist.netset";
            if (!File.Exists(path)) return;
            int loaded = 0;
            foreach (var line in File.ReadAllLines(path))
            {
                if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var p = line.Split('/');
                    if (p.Length == 2)
                    { BlacklistCidrs.Add((IPAddress.Parse(p[0].Trim()), int.Parse(p[1].Trim()))); loaded++; }
                }
                catch { }
            }
            LogInfo($"Loaded {loaded} FireHOL CIDRs.");
        }

        private static bool IsFireholBlacklisted(string ipStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) return false;
            foreach (var (net, mask) in BlacklistCidrs)
                if (IsIpInCidr(ip, net, mask)) return true;
            return false;
        }

        private static bool IsIpInCidr(IPAddress ip, IPAddress net, int mask)
        {
            byte[] a = ip.GetAddressBytes(), b = net.GetAddressBytes();
            if (a.Length != b.Length) return false;
            int bits = mask;
            for (int i = 0; i < a.Length && bits > 0; i++)
            {
                int s = Math.Min(bits, 8);
                byte m = (byte)(0xFF << (8 - s));
                if ((a[i] & m) != (b[i] & m)) return false;
                bits -= s;
            }
            return true;
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
                foreach (var prefix in CdnIpPrefixes)
                    if (host.StartsWith(prefix)) return true;
                if (IsCloudflareIp(host)) return true;
                if (IsFireholBlacklisted(host)) return true;
            }

            return false;
        }

        // ====================== LOCATION ======================
        private string GetLocation(string host)
        {
            try
            {
                var city = Resolver.GetCity(host);
                if (!string.IsNullOrEmpty(city?.CityName))
                {
                    string flag = Flags.TryGetValue(city.CountryCode?.ToUpper() ?? "", out var f) ? f : "🌍";
                    return $"{flag} {city.CityName}, {city.CountryCode?.ToUpper()}";
                }
                var country = Resolver.GetCountry(host);
                string cc = country?.CountryCode?.ToUpper() ?? "";
                if (!string.IsNullOrEmpty(cc) && cc != "XX")
                {
                    string flagC = Flags.TryGetValue(cc, out var fc) ? fc : "🌍";
                    string name = !string.IsNullOrEmpty(country?.CountryName) && country.CountryName != "Unknown"
                        ? country.CountryName : cc;
                    return $"{flagC} {name}";
                }
                if (!IPAddress.TryParse(host, out _))
                {
                    try
                    {
                        var addrs = Dns.GetHostAddresses(host);
                        if (addrs.Length > 0)
                        {
                            var c2 = Resolver.GetCountry(addrs[0].ToString());
                            string cc2 = c2?.CountryCode?.ToUpper() ?? "";
                            if (!string.IsNullOrEmpty(cc2) && cc2 != "XX")
                            {
                                string f2 = Flags.TryGetValue(cc2, out var ff2) ? ff2 : "🌍";
                                string n2 = !string.IsNullOrEmpty(c2?.CountryName) && c2.CountryName != "Unknown"
                                    ? c2.CountryName : cc2;
                                return $"{f2} {n2}";
                            }
                        }
                    }
                    catch { }
                }
                return "🌐 Unknown";
            }
            catch { return "🌐 Unknown"; }
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
            await DownloadFreshFireHOLBlacklist(_http);
            LoadAllBlacklists();
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

            LogInfo($"After smart dedup: {uniqueProxies.Count} unique ({cfFiltered} CDN/blacklist filtered)");

            // STEP 3: TCP alive check
            LogInfo("🔌 TCP alive check (parallel)...");
            var aliveBag = new ConcurrentBag<(ParsedProxy Proxy, int Latency)>();

            await Parallel.ForEachAsync(uniqueProxies, new ParallelOptions { MaxDegreeOfParallelism = 200 },
                async (p, _) =>
                {
                    int lat = await TcpProbe(p.Host, p.Port);
                    if (lat >= 0) aliveBag.Add((p, lat));
                });

            var alive = aliveBag
                .OrderByDescending(x => x.Proxy.QualityScore)
                .ThenBy(x => x.Latency)
                .ToList();

            LogSuccess($"Alive proxies: {alive.Count}");

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
            var remarkTotal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in alive)
            {
                var p = item.Proxy;
                string baseRemark = $"{Loc(p.Host)} | {NormalizeProto(p.Protocol).ToUpperInvariant()} | {p.Host}:{p.Port}";
                remarkTotal.TryGetValue(baseRemark, out int cnt);
                remarkTotal[baseRemark] = cnt + 1;
            }

            // Pass 2: assign remarks — unique nodes get no suffix, duplicates get #1, #2, #3...
            var remarkCounter = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in alive)
            {
                var p = item.Proxy;
                string proto = NormalizeProto(p.Protocol);
                string baseRemark = $"{Loc(p.Host)} | {proto.ToUpperInvariant()} | {p.Host}:{p.Port}";

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
                var clashProxy = BuildClashProxyDict(p, remark);

                finalProxies.Add(new FinalProxy
                {
                    Link = cleanLink, Proto = proto, CountryCode = cc,
                    Continent = continent, Remark = remark,
                    ClashProxyDict = clashProxy,
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

        // ====================== BUILD CLASH PROXY DICT ======================
        // Returns a Dictionary<string,object> suitable for direct YAML serialization
        private static Dictionary<string, object?>? BuildClashProxyDict(ParsedProxy p, string name)
        {
            try
            {
                string proto = NormalizeProto(p.Protocol);
                int port = int.TryParse(p.Port, out int pp) ? pp : 443;

                switch (proto)
                {
                    case "vless":
                    {
                        var d = new Dictionary<string, object?>
                        {
                            ["name"]             = name,
                            ["type"]             = "vless",
                            ["server"]           = p.Host,
                            ["port"]             = port,
                            ["uuid"]             = p.Credential,
                            ["tls"]              = p.Security is "tls" or "reality",
                            ["network"]          = string.IsNullOrEmpty(p.Network) ? "tcp" : p.Network,
                            ["skip-cert-verify"] = true,
                        };
                        if (!string.IsNullOrEmpty(p.Sni)) d["servername"] = p.Sni;
                        if (p.Security == "reality")      d["reality-opts"] = new Dictionary<string, object?> { ["public-key"] = "" };
                        if (!string.IsNullOrEmpty(p.Path) && p.Network == "ws")
                            d["ws-opts"] = new Dictionary<string, object?> { ["path"] = p.Path };
                        if (!string.IsNullOrEmpty(p.Path) && p.Network == "grpc")
                            d["grpc-opts"] = new Dictionary<string, object?> { ["grpc-service-name"] = p.Path };
                        return d;
                    }
                    case "trojan":
                    {
                        var d = new Dictionary<string, object?>
                        {
                            ["name"]             = name,
                            ["type"]             = "trojan",
                            ["server"]           = p.Host,
                            ["port"]             = port,
                            ["password"]         = p.Credential,
                            ["skip-cert-verify"] = true,
                        };
                        if (!string.IsNullOrEmpty(p.Sni)) d["sni"] = p.Sni;
                        if (!string.IsNullOrEmpty(p.Network) && p.Network != "tcp")
                            d["network"] = p.Network;
                        if (!string.IsNullOrEmpty(p.Path) && p.Network == "ws")
                            d["ws-opts"] = new Dictionary<string, object?> { ["path"] = p.Path };
                        if (!string.IsNullOrEmpty(p.Path) && p.Network == "grpc")
                            d["grpc-opts"] = new Dictionary<string, object?> { ["grpc-service-name"] = p.Path };
                        return d;
                    }
                    case "ss":
                    {
                        string method = "", password = "";
                        string ui = p.Credential;
                        try
                        {
                            int pd = ui.Length % 4; if (pd > 0) ui += new string('=', 4 - pd);
                            var dec = Encoding.UTF8.GetString(Convert.FromBase64String(ui));
                            int c = dec.IndexOf(':');
                            if (c > 0) { method = dec[..c]; password = dec[(c + 1)..]; }
                        }
                        catch
                        {
                            int c = ui.IndexOf(':');
                            if (c > 0) { method = ui[..c]; password = ui[(c + 1)..]; }
                        }
                        return new Dictionary<string, object?>
                        {
                            ["name"] = name, ["type"] = "ss",
                            ["server"] = p.Host, ["port"] = port,
                            ["cipher"] = method, ["password"] = password
                        };
                    }
                    case "hysteria2":
                        return new Dictionary<string, object?>
                        {
                            ["name"]             = name,
                            ["type"]             = "hysteria2",
                            ["server"]           = p.Host,
                            ["port"]             = port,
                            ["password"]         = p.Credential,
                            ["sni"]              = string.IsNullOrEmpty(p.Sni) ? p.Host : p.Sni,
                            ["skip-cert-verify"] = true,
                        };
                    case "vmess":
                    {
                        var d = new Dictionary<string, object?>
                        {
                            ["name"]             = name,
                            ["type"]             = "vmess",
                            ["server"]           = p.Host,
                            ["port"]             = port,
                            ["uuid"]             = p.Credential,
                            ["alterId"]          = p.Aid,
                            ["cipher"]           = "auto",
                            ["network"]          = string.IsNullOrEmpty(p.Network) ? "tcp" : p.Network,
                            ["tls"]              = p.Security == "tls",
                            ["skip-cert-verify"] = true,
                        };
                        if (!string.IsNullOrEmpty(p.Sni)) d["servername"] = p.Sni;
                        if (!string.IsNullOrEmpty(p.Path) && p.Network == "ws")
                            d["ws-opts"] = new Dictionary<string, object?> { ["path"] = p.Path };
                        if (!string.IsNullOrEmpty(p.Path) && p.Network == "grpc")
                            d["grpc-opts"] = new Dictionary<string, object?> { ["grpc-service-name"] = p.Path };
                        return d;
                    }
                    default: return null;
                }
            }
            catch { return null; }
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
        private async Task SaveAllCategories(List<FinalProxy> proxies)
        {
            var sub = Path.Combine(Directory.GetCurrentDirectory(), "sub");
            foreach (var d in new[] { "protocols", "countries", "continents" })
                Directory.CreateDirectory(Path.Combine(sub, d));

            // everything.txt — full list, no cap, no YAML (too large)
            await File.WriteAllLinesAsync(Path.Combine(sub, "everything.txt"), proxies.Select(x => x.Link));
            LogSuccess($"Saved everything.txt ({proxies.Count})");

            foreach (var g in proxies.GroupBy(x => x.Proto))
            {
                string key = g.Key.Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(key) || key == "unknown") continue;

                await WriteTxtAndYaml(Path.Combine(sub, "protocols", key), g.ToList());
                LogSuccess($"  → protocols/{key} ({g.Count()})");
            }

            foreach (var g in proxies.GroupBy(x => x.CountryCode))
            {
                if (string.IsNullOrEmpty(g.Key) || g.Key == "XX" || g.Count() < 3) continue;
                string safe = Regex.Replace(g.Key, @"[^A-Z0-9]", "");
                if (string.IsNullOrEmpty(safe)) continue;
                await WriteTxtAndYaml(Path.Combine(sub, "countries", safe), g.ToList());
                LogSuccess($"  → countries/{safe} ({g.Count()})");
            }

            foreach (var g in proxies.GroupBy(x => x.Continent))
            {
                if (g.Key == "Unknown" || g.Count() < 3) continue;
                await WriteTxtAndYaml(Path.Combine(sub, "continents", g.Key), g.ToList());
                LogSuccess($"  → continents/{g.Key} ({g.Count()})");
            }
        }

        // ====================== WRITE TXT + YAML ======================
        // .txt  → full list, plain URI format, one per line
        // .yaml → Clash/Mihomo/FlClash compatible, capped at 1000 best nodes
        private static async Task WriteTxtAndYaml(string pathNoExt, List<FinalProxy> proxies)
        {
            // Full plain-text URI list
            await File.WriteAllLinesAsync(pathNoExt + ".txt", proxies.Select(x => x.Link));

            // Clash YAML — best 1000 only
            const int YamlCap = 1000;
            var subset = proxies.Count > YamlCap ? proxies.Take(YamlCap).ToList() : proxies;

            var validProxies = subset
                .Select(x => x.ClashProxyDict)
                .Where(d => d != null)
                .ToList();

            var names = subset
                .Where(x => x.ClashProxyDict != null)
                .Select(x => x.Remark)
                .ToList();

            string categoryName = Path.GetFileName(pathNoExt);
            var yaml = new StringBuilder();

            // Clash/Mihomo YAML header
            yaml.AppendLine($"# FastNodes — {categoryName}");
            yaml.AppendLine($"# Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC");
            yaml.AppendLine($"# Proxies: {validProxies.Count} (capped at {YamlCap} best quality)");
            yaml.AppendLine($"# Compatible: Clash Meta / Mihomo / FlClash / FlClashX");
            yaml.AppendLine();
            yaml.AppendLine("mixed-port: 7890");
            yaml.AppendLine("allow-lan: true");
            yaml.AppendLine("mode: rule");
            yaml.AppendLine("log-level: info");
            yaml.AppendLine("external-controller: 127.0.0.1:9090");
            yaml.AppendLine("dns:");
            yaml.AppendLine("  enable: true");
            yaml.AppendLine("  enhanced-mode: fake-ip");
            yaml.AppendLine("  nameserver:");
            yaml.AppendLine("    - 8.8.8.8");
            yaml.AppendLine("    - 1.1.1.1");
            yaml.AppendLine();
            yaml.AppendLine("proxies:");

            foreach (var proxy in validProxies!)
                AppendClashProxyYaml(yaml, proxy!);

            yaml.AppendLine();
            yaml.AppendLine("proxy-groups:");
            yaml.AppendLine($"  - name: \"{categoryName}\"");
            yaml.AppendLine("    type: url-test");
            yaml.AppendLine("    url: http://cp.cloudflare.com/generate_204");
            yaml.AppendLine("    interval: 300");
            yaml.AppendLine("    tolerance: 50");
            yaml.AppendLine("    proxies:");
            foreach (var name in names)
                yaml.AppendLine($"      - \"{EscapeYamlString(name)}\"");

            yaml.AppendLine($"  - name: \"AUTO\"");
            yaml.AppendLine("    type: select");
            yaml.AppendLine("    proxies:");
            foreach (var name in names)
                yaml.AppendLine($"      - \"{EscapeYamlString(name)}\"");

            yaml.AppendLine();
            yaml.AppendLine("rules:");
            yaml.AppendLine("  - MATCH,AUTO");

            await File.WriteAllTextAsync(pathNoExt + ".yaml", yaml.ToString());
        }

        // ====================== YAML PROXY SERIALIZER ======================
        private static void AppendClashProxyYaml(StringBuilder sb, Dictionary<string, object?> proxy)
        {
            sb.AppendLine("  - " + YamlKeyValue("name", proxy.GetValueOrDefault("name")));

            foreach (var kv in proxy)
            {
                if (kv.Key == "name") continue;

                if (kv.Value is Dictionary<string, object?> nested)
                {
                    sb.AppendLine($"    {kv.Key}:");
                    foreach (var nkv in nested)
                        sb.AppendLine("      " + YamlKeyValue(nkv.Key, nkv.Value));
                }
                else
                {
                    sb.AppendLine("    " + YamlKeyValue(kv.Key, kv.Value));
                }
            }
        }

        private static string YamlKeyValue(string key, object? value)
        {
            return value switch
            {
                null          => $"{key}: ~",
                bool b        => $"{key}: {(b ? "true" : "false")}",
                int i         => $"{key}: {i}",
                string s      => $"{key}: \"{EscapeYamlString(s)}\"",
                _             => $"{key}: \"{EscapeYamlString(value.ToString() ?? "")}\"",
            };
        }

        private static string EscapeYamlString(string s)
            => s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");

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
        public Dictionary<string, object?>? ClashProxyDict { get; set; }
        public int     Latency          { get; set; }
        public int     QualityScore     { get; set; }
    }
}
