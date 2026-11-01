using System.Net;
using System.Net.Sockets;
using System.Text;
using MFirewallApp.Interface;

namespace MFirewallApi.Networking;

public class ProxyTcpDispatcher : IProxyDispatcher
{
    private readonly ITunelHandler _connectTunelHandler;

    private const int KestrelPort = 5120;

    public ProxyTcpDispatcher(ITunelHandler tunelHandler)
    {
        _connectTunelHandler = tunelHandler;
    }

    public async Task DispatchAsync(
        TcpClient client,
        CancellationToken cancellationToken)
    {
        NetworkStream clientStream = client.GetStream();

        
        Console.WriteLine("[Dispatcher] Started");

var header = await ConnectTunelHandler.ReadHttpHeaderAsync(
    clientStream,
    cancellationToken);

Console.WriteLine("[Dispatcher] Header received");

string headerText = Encoding.ASCII.GetString(header.HeaderBytes);

var requestLine = headerText.Split("\r\n")[0];

Console.WriteLine($"[Dispatcher] Request: {requestLine}");

var parts = requestLine.Split(
    ' ',
    StringSplitOptions.RemoveEmptyEntries);

string method = parts[0];

if (HttpMethods.IsConnect(method))
{
    Console.WriteLine("[Dispatcher] CONNECT detected");

    await _connectTunelHandler.HandleClientAsync(
        client,
        headerText,
        header.RemainingBytes,
        cancellationToken);

    Console.WriteLine("[Dispatcher] CONNECT handler completed");
    return;
}

Console.WriteLine("[Dispatcher] HTTP request detected");

      
        await ForwardToKestrelAsync(
            clientStream,
            header,
            cancellationToken);
    }

    private static async Task ForwardToKestrelAsync(
        NetworkStream clientStream,
        HttpHeaderReaderResult header,
        CancellationToken cancellationToken)
    {
        using var kestrelClient = new TcpClient();

        await kestrelClient.ConnectAsync(
            IPAddress.Loopback,
            KestrelPort,
            cancellationToken);

        using NetworkStream kestrelStream =
            kestrelClient.GetStream();

      
        await kestrelStream.WriteAsync(
            header.HeaderBytes.AsMemory(),
            cancellationToken);

       
        if (header.RemainingBytes.Length > 0)
        {
            await kestrelStream.WriteAsync(
                header.RemainingBytes.AsMemory(),
                cancellationToken);
        }

        var clientToKestrel = clientStream.CopyToAsync(
            kestrelStream,
            cancellationToken);

        var kestrelToClient = kestrelStream.CopyToAsync(
            clientStream,
            cancellationToken);

        await Task.WhenAll(
            clientToKestrel,
            kestrelToClient);
    }

    private static async Task SendErrorAsync(
        NetworkStream stream,
        int statusCode,
        string reason,
        CancellationToken cancellationToken)
    {
        string response =
            $"HTTP/1.1 {statusCode} {reason}\r\n" +
            "Connection: close\r\n" +
            "Content-Length: 0\r\n\r\n";

        await stream.WriteAsync(
            Encoding.ASCII.GetBytes(response).AsMemory(),
            cancellationToken);
    }

   
}