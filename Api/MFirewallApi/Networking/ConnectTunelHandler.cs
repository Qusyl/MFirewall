using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using MFirewallApp.Crypto.Token;
using MFirewallApp.Interface;
using MFirewallApp.Rules;
using Microsoft.Extensions.Options;

namespace MFirewallApi.Networking
{
    public class ConnectTunelHandler : ITunelHandler
    {
        private readonly IOptionsMonitor<HttpProxyConfiguration> _config;
        private readonly IOptions<JwtOptions> _jwt;
        public ConnectTunelHandler(IOptionsMonitor<HttpProxyConfiguration> config, IOptions<JwtOptions> jwt)
        {
            _config = config;
            _jwt = jwt;
        }
        public  async Task HandleClientAsync(
           TcpClient client,
            string headerText,
            byte[] remainingBytes,
           CancellationToken cancellationToken)
        {
            using (client)
            {
                try
                {
                    Console.WriteLine("[Tunnel] Handler started");
                    using NetworkStream stream = client.GetStream();

                    Console.WriteLine("Client connected");
                    (string host, int port) pair = ParseConnectRequest(headerText);

                    System.Console.WriteLine($"Host = {pair.host}");
                    System.Console.WriteLine($"Port = {pair.port}");

                    var forbiddenPorts = _config.CurrentValue.HttpsOptions.AllowedPorts;

                    var forbiddenDomain = _config.CurrentValue.BlackListDomainOptions.BlackList;

                    var allowedDomain = _config.CurrentValue.AllowedDomainOptions.AllowedDomains;

                    if (!forbiddenPorts.Contains(pair.port))
                    {
                        await SendProxyResponseAsync(stream, 403, "Port not found on allowed list", cancellationToken);
                        return;
                    }
                    if (forbiddenDomain.Contains(pair.host))
                    {
                        await SendProxyResponseAsync(stream, 403, "Host found on forbidden list", cancellationToken);
                        return;
                    }

                    if (!allowedDomain.Contains("*")
                    && !allowedDomain.Contains(pair.host, StringComparer.OrdinalIgnoreCase))
                    {
                        await SendProxyResponseAsync(stream, 403, "Host found on forbidden list", cancellationToken);
                        return;
                    }
                    Console.WriteLine("[Tunnel] Policy validated");

                    Console.WriteLine("[Tunnel] Connecting to destination");
                 

                    Console.WriteLine("[Tunnel] Extracting JWT");
                    var jwtText = ExtractJwtToken(headerText);
                    var jwtValidator = new MFirewallApp.Validators.JwtValidator(_jwt);
                    Console.WriteLine("[Tunnel] JWT validated");

                    if (!jwtValidator.TryValidate(jwtText, out var payload))
                    {
                        await SendProxyResponseAsync(stream, 407, "Proxy Authentication Required", cancellationToken);
                        return;
                    }

                    using var destClient = new TcpClient();

                    await destClient.ConnectAsync(pair.host, pair.port, cancellationToken);
                    Console.WriteLine("[Tunnel] Destination connected");
                    System.Console.WriteLine($"Connected to {pair.host}:{pair.port}");
                    await SendConnectEstablishedAsync(stream, cancellationToken);

                    using NetworkStream destStream = destClient.GetStream();

                    if (remainingBytes.Length > 0)
                    {
                        await destStream.WriteAsync(remainingBytes.AsMemory(), cancellationToken);
                    }

                    var clientToServer = stream.CopyToAsync(destStream, cancellationToken);

                    var serverToClient = destStream.CopyToAsync(stream, cancellationToken);

                    await Task.WhenAll(clientToServer, serverToClient);

                    // await stream.WriteAsync(response, cancellationToken);
                }
                catch (SocketException ex)
                {
                    System.Console.WriteLine($"Connection failed : {ex.Message}");

                    if (client.Connected)
                    {
                        try
                        {
                            using var stream = client.GetStream();

                            await SendProxyResponseAsync(stream, 502, "Bad Gateway", cancellationToken); ;
                        }
                        catch
                        {

                        }
                    }
                }
                catch (OperationCanceledException op)
                {
                    System.Console.WriteLine("Connection cancelled");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Client error: {ex.Message}");
                }
            }
        }
    private static async Task SendProxyResponseAsync(
    NetworkStream stream,
    int statusCode,
    string reason,
    CancellationToken cancellationToken)
{
    var response =
        $"HTTP/1.1 {statusCode} {reason}\r\n" +
        "Connection: close\r\n" +
        "Content-Length: 0\r\n" +
        "\r\n";

    await stream.WriteAsync(
        Encoding.ASCII.GetBytes(response).AsMemory(),
        cancellationToken);
}
        private static async Task SendConnectEstablishedAsync(
    NetworkStream stream,
    CancellationToken cancellationToken)
{
    var response = Encoding.ASCII.GetBytes(
        "HTTP/1.1 200 Connection Established\r\n\r\n");

    await stream.WriteAsync(
        response.AsMemory(),
        cancellationToken);
}
        private static (string Host, int Port) ParseConnectRequest(
    string headerText)
        {
            var lines = headerText.Split("\r\n");

            var parts = lines[0].Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length != 3 ||
                !parts[0].Equals("CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Invalid CONNECT request");
            }

            var authority = parts[1];


            bool hasPort;

            if (authority.StartsWith("["))
            {

                int closingBracket = authority.IndexOf(']');

                hasPort = closingBracket > 0 &&
                          closingBracket + 1 < authority.Length &&
                          authority[closingBracket + 1] == ':';
            }
            else
            {

                hasPort = authority.Count(c => c == ':') == 1;
            }

            if (!hasPort ||
                !Uri.TryCreate(
                    $"https://{authority}",
                    UriKind.Absolute,
                    out var uri))
            {
                throw new InvalidDataException("Invalid CONNECT target");
            }

            if (!string.IsNullOrEmpty(uri.UserInfo) ||
                uri.AbsolutePath != "/" ||
                !string.IsNullOrEmpty(uri.Query) ||
                !string.IsNullOrEmpty(uri.Fragment))
            {
                throw new InvalidDataException("Invalid CONNECT authority");
            }

            string host = uri.Host.Trim('[', ']');
            int port = uri.Port;

            if (port < 1 || port > 65535)
            {
                throw new InvalidDataException("Invalid port");
            }

            return (host, port);
        }



        public async static Task<HttpHeaderReaderResult> ReadHttpHeaderAsync(NetworkStream stream, CancellationToken cts)
        {
            const int maxHeaderSize = 16 * 1024;

            var collected = new List<byte>();

            var buffer = new byte[1024];

            while (true)
            {
                int bytesRead = await stream.ReadAsync(buffer, cts);

                if (bytesRead == 0)
                {
                    throw new EndOfStreamException("Client отключился до полного чтения HTTP HEADER");
                }

                for (int i = 0; i < bytesRead; i++)
                {
                    collected.Add(buffer[i]);

                    int count = collected.Count;

                    if (count >= 4 &&
                    collected[count - 4] == 13 &&
                    collected[count - 3] == 10 &&
                    collected[count - 2] == 13 &&
                    collected[count - 1] == 10)
                    {
                        int remainingCount = bytesRead - i - 1;

                        byte[] remainingData = buffer
                        .AsSpan(i + 1, remainingCount)
                        .ToArray();

                        return new HttpHeaderReaderResult(collected.ToArray(), remainingData);

                    }

                    if (count > maxHeaderSize)
                    {
                        throw new InvalidDataException("HTTP header is too long");
                    }
                }

            }
        }
         private  static string? ExtractJwtToken(string header)
        {
            var lines = header.Split(
                "\r\n",
                StringSplitOptions.RemoveEmptyEntries
            );

            var authHeader = lines
            .Skip(1)
            .Where(line =>
            line.StartsWith(
                "Proxy-Authorization:",
                StringComparison.OrdinalIgnoreCase
            ))
            .ToArray();

            if (authHeader.Length != 1)
            {
                return null;
            }

            int separator = authHeader[0].IndexOf(':');

            var value = authHeader[0][(separator + 1)..].Trim();

            const string bearerPrefix = "Bearer ";

            if (!value.StartsWith(
                bearerPrefix, StringComparison.OrdinalIgnoreCase
            ))
            {
                return null;
            }

            var token = value[bearerPrefix.Length..].Trim();

            return string.IsNullOrEmpty(token) ? null : token;
        }
    }
    
}