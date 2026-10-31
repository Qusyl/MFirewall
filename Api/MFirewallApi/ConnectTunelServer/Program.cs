using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace ConnectTunelServer.Program
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            using var server = new TcpListener(
                IPAddress.Loopback, 5119);

            using var cts = new CancellationTokenSource();

            server.Start();

            Console.WriteLine("CONNECT server started");

            try
            {
                while (!cts.IsCancellationRequested)
                {
                    TcpClient client = await server.AcceptTcpClientAsync(
                        cts.Token);

                    _ = HandleClientAsync(client, cts.Token);
                }
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("Server stopped");
            }
            finally
            {
                server.Stop();
            }
        }

        private static async Task HandleClientAsync(
            TcpClient client,
            CancellationToken cancellationToken)
        {
            using (client)
            {
                try
                {
                    using NetworkStream stream = client.GetStream();

                    Console.WriteLine("Client connected");

                    byte[] header = await ReadHttpHeaderAsync(stream, cancellationToken);

                    string headerText = Encoding.ASCII.GetString(header);

                    Console.WriteLine("Received HTTP header:");
                    Console.WriteLine(headerText);


                    (string host, int port) pair = ParseConnectRequest(headerText);

                    System.Console.WriteLine($"Host = {pair.host}");
                    System.Console.WriteLine($"Port = {pair.port}");

                    using var destClient = new TcpClient();

                    await destClient.ConnectAsync(pair.host, pair.port, cancellationToken);

                    System.Console.WriteLine($"Connected to {pair.host}:{pair.port}");

                    using NetworkStream destStream = destClient.GetStream();
                    string response =
                    $"HTTP/1.1 {111} just\r\n" +
                    "Connection: close\r\n" +
                    "Content-Length: 0\r\n" +
                    "\r\n";

                    await destStream.WriteAsync(Encoding.ASCII.GetBytes($"Hell"));



                    // await stream.WriteAsync(response, cancellationToken);
                }catch(SocketException ex)
                {
                    System.Console.WriteLine($"Connection failed : {ex.Message}");

                    if (client.Connected)
                    {
                        try
                        {
                            using var stream = client.GetStream();

                            await stream.WriteAsync(Encoding.ASCII.GetBytes("StatusCode: 502 {Bad Gateway}"));
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

       
        
        private async static Task<byte[]> ReadHttpHeaderAsync(NetworkStream stream, CancellationToken cts)
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
                        return collected.ToArray();
                    }

                    if(count > maxHeaderSize)
                    {
                        throw new InvalidDataException("HTTP header is too long");
                    }
                }
                
            }
        }
    }
}