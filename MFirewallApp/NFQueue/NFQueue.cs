using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Threading.Channels;
using Domain.Models;
using Domain.Values;
using MFirewallApp.FileSystem;

namespace MFirewallApp.NFQueue
{
    public class NFQueue
    {
        private const string LibNetfilterQueue = "libnetfilter_queue.so.1";

        private const uint NF_ACCEPT = 1;
        private const uint NF_DROP = 0;

        private const ushort AF_INET = 2;
        private const byte NFQNL_COPY_PACKET = 2;

        private const short POLLIN = 0x0001;
        private const int ENOBUFS = 105;

        private IntPtr _queueHandle;

        private static Channel<CapturedPacket> _channel;

        public NFQueue()
        {
            _channel = Channel.CreateBounded<CapturedPacket>(5000);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct NfqlHeader
        {
            public uint packet_id;
            public ushort hw_protocol;
            public byte hook;
        }
        

        [StructLayout(LayoutKind.Sequential)]
        private struct PollFd
        {
            public int fd;
            public short events;
            public short revents;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int nfq_callback(
    IntPtr qh,
    IntPtr nfmsg,
    IntPtr nfa,
    IntPtr data);

        [DllImport(LibNetfilterQueue)] private static extern IntPtr nfq_open();
        [DllImport(LibNetfilterQueue)] private static extern int nfq_unbind_pf(IntPtr h, ushort pf);
        [DllImport(LibNetfilterQueue)] private static extern int nfq_bind_pf(IntPtr h, ushort pf);
        [DllImport(LibNetfilterQueue)] private static extern IntPtr nfq_create_queue(IntPtr h, ushort num, nfq_callback cb, IntPtr data);
        [DllImport(LibNetfilterQueue)] private static extern int nfq_destroy_queue(IntPtr qh);
        [DllImport(LibNetfilterQueue)] private static extern int nfq_set_mode(IntPtr qh, byte mode, uint len);
        [DllImport(LibNetfilterQueue)] private static extern int nfq_close(IntPtr h);
        [DllImport(LibNetfilterQueue)] private static extern int nfq_fd(IntPtr h);
        [DllImport(LibNetfilterQueue)] private static extern int nfq_handle_packet(IntPtr h, byte[] buf, int len);
        [DllImport(LibNetfilterQueue)] private static extern int nfq_set_verdict(IntPtr qh, uint id, uint verdict, uint dataLen, IntPtr buf);
        [DllImport(LibNetfilterQueue)] private static extern IntPtr nfq_get_msg_packet_hdr(IntPtr nfad);
        [DllImport(LibNetfilterQueue)] private static extern int nfq_get_payload(IntPtr nfad, out IntPtr data);

        [DllImport("libc.so.6", SetLastError = true)]
        private static extern int recv(int fd, byte[] buf, UIntPtr len, int flags);

        [DllImport("libc.so.6", SetLastError = true)]
        private static extern int poll([In, Out] PollFd[] fds, ulong nfds, int timeout);

      
        private static nfq_callback? _callBackDelegate;

        private static void Log(string message) =>
            FileLogger.AppendLogFile($"[{DateTime.UtcNow:dd-MM-yyyy HH:mm:ss}] {message}");

        public ChannelReader<CapturedPacket> Reader()
        {
            return _channel.Reader;
        }
        
        private static bool TryWrite(CapturedPacket packet)
        {
            return _channel.Writer.TryWrite(packet);
        }

        public Task OpenNfqueueAsync(CancellationToken ct) =>
            Task.Run(() => Run(ct), ct);

        public void SetVerdict(Verdict.Verdict verdict, uint Id)
        {
            if (verdict is Verdict.Verdict.ACCEPT)
            {
                nfq_set_verdict(_queueHandle, Id, NF_ACCEPT, 0, IntPtr.Zero);
            }
            else
            {
                nfq_set_verdict(_queueHandle, Id, NF_DROP, 0, IntPtr.Zero);
            }
        }


        private void Run(CancellationToken ct)
        {
            Log("Открываем nfqueue...");

            IntPtr h = nfq_open();
            if (h == IntPtr.Zero)
            {
                Log("NFQueue: не удалось открыть nfq_open()!");
                return;
            }

            IntPtr qh = IntPtr.Zero;

            try
            {
                if (!NfqBind(h)) return;

                qh = CreateQueue(h);
                if (qh == IntPtr.Zero) return;
                _queueHandle = qh;
                int fd = nfq_fd(h);
                byte[] buffer = new byte[65536];
                var pfd = new[] { new PollFd { fd = fd, events = POLLIN } };

                Log("NFQueue: запущен и готов к работе!");

                while (!ct.IsCancellationRequested)
                {

                    int pr = poll(pfd, 1, 500);
                    if (pr == 0) continue;
                    if (pr < 0)
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == 4) continue;
                        Log($"NFQueue: ошибка poll, errno={err}");
                        break;
                    }

                    int rev = recv(fd, buffer, (UIntPtr)buffer.Length, 0);
                    if (rev < 0)
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == ENOBUFS)
                        {
                            Log("NFQueue: переполнение очереди, пакеты потеряны");
                            continue;
                        }
                        Log($"NFQueue: ошибка recv, errno={err}");
                        break;
                    }
                    if (rev == 0) continue;


                    nfq_handle_packet(h, buffer, rev);
                }

                Log("NFQueue: принудительное завершение работы!");
            }
            catch (Exception ex)
            {
                Log($"NFQueue: аварийное завершение работы - {ex.Message}!");
            }
            finally
            {
                if (qh != IntPtr.Zero) nfq_destroy_queue(qh);
                nfq_close(h);
            }
        }

        private static bool NfqBind(IntPtr h)
        {
            Log("NFQueue: привязывание протокола...");
            nfq_unbind_pf(h, AF_INET);
            if (nfq_bind_pf(h, AF_INET) < 0)
            {
                Log("NFQueue: ошибка привязки протокола!");
                return false;
            }
            Log("NFQueue: привязывание протокола успешно!");
            return true;
        }

        private static IntPtr CreateQueue(IntPtr h)
        {
            Log("NFQueue: создание очереди...");
            _callBackDelegate = PacketCallback;

            IntPtr qh = nfq_create_queue(h, 0, _callBackDelegate, IntPtr.Zero);
            if (qh == IntPtr.Zero)
            {
                Log("NFQueue: не удалось создать очередь!");
                return IntPtr.Zero;
            }

            if (!SetCopyMode(qh))
            {
                nfq_destroy_queue(qh);
                return IntPtr.Zero;
            }

            Log("NFQueue: очередь успешно создана!");
            return qh;
        }

        private static bool SetCopyMode(IntPtr qh)
        {
            Log("NFQueue: установка режима копирования...");
            if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
            {
                Log("NFQueue: ошибка установки режима копирования!");
                return false;
            }
            Log("NFQueue: режим копирования успешно установлен!");
            return true;
        }

        private static int PacketCallback(IntPtr qh, IntPtr nfmsg, IntPtr nfa, IntPtr data)
        {
            uint id = 0;
            try
            {
                IntPtr ph = nfq_get_msg_packet_hdr(nfa);
                if (ph == IntPtr.Zero) return 0;

                var hdr = Marshal.PtrToStructure<NfqlHeader>(ph);
                id = BinaryPrimitives.ReverseEndianness(hdr.packet_id);

                byte[] payload = Array.Empty<byte>();
                int len = nfq_get_payload(nfa, out IntPtr payloadPtr);
                if (len > 0 && payloadPtr != IntPtr.Zero)
                {
                    payload = new byte[len];
                    Marshal.Copy(payloadPtr, payload, 0, len);
                }

                var packet = new CapturedPacket(id, payload);

                TryWrite(packet);
        
                return 1;
            }catch(Exception ex)
            {
                Log(ex.Message);
                return 0;
            }
    } 
} 
    
}