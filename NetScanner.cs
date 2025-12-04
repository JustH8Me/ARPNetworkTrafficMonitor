using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;
//сам сканер
namespace ArpTrafficMonitor
{
    internal class NetScanner
    {
        private ICaptureDevice _device;

        private IPAddress? _myIp;
        private string _baseIp;
        private bool _isScanning;
        private readonly object _syncLock = new object();
        public List<FoundDevice> FoundDevices { get; private set; } = new List<FoundDevice>();
        public event Action<FoundDevice>? DeviceFound;
        public NetScanner(ICaptureDevice device, string myIp, string baseIp)
        {
            _device = device;
            if (!IPAddress.TryParse(myIp, out _myIp))
            {
                throw new ArgumentException("ERROR invalid IP");
            }
            _baseIp = baseIp;
            _device.OnPacketArrival += Device_OnPkgArr;
        }

        public void Start()
        {
            _device.Open(DeviceModes.Promiscuous, 10);
            _device.Filter = "arp";
            _device.StartCapture();
            _isScanning = true;
            Task.Run(() => SendRequestsLoop());
        }
        public void Stop()
        {
            _isScanning = false;
            try
            {
                _device.StopCapture();
            }
            catch
            {
                throw new ArgumentException("ERROR invalid command");
            }
        }

        private void SendRequestsLoop()
        {
            var broadCastMac = PhysicalAddress.Parse("FFFFFFFFFFFF");
            var zeroMac = PhysicalAddress.Parse("000000000000");

            while (_isScanning)
            {
                // TODO: ddd subnet mask calculation
                for (int i = 1; i < 255; i++)
                {
                    if (!_isScanning) break;
                    string targetIpStr = _baseIp + i;
                    if (_myIp != null && targetIpStr == _myIp.ToString()) continue;
                    IPAddress targetIp = IPAddress.Parse(targetIpStr);
                    SendArpRequest(targetIp, zeroMac, broadCastMac);
                    Thread.Sleep(5);
                }
                Thread.Sleep(1000);
            }
        }
        //конструкотр и отправка АРП
        private void SendArpRequest(IPAddress scanIp, PhysicalAddress zeroMac, PhysicalAddress broadCastMac)
        {
            var arp = new ArpPacket(
                ArpOperation.Request,
                targetHardwareAddress: zeroMac,
                targetProtocolAddress: scanIp,
                senderHardwareAddress: _device.MacAddress,
                senderProtocolAddress: _myIp

                );
            var ethernetpcg = new EthernetPacket(
                _device.MacAddress,
                broadCastMac,
                EthernetType.Arp
                );
            ethernetpcg.PayloadPacket = arp;
            var realCard = (SharpPcap.LibPcap.LibPcapLiveDevice)_device;
            realCard.SendPacket(ethernetpcg);

        }
        
        private void Device_OnPkgArr(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            var arpPacket = packet.Extract<ArpPacket>();
            if (arpPacket == null) return;
            if (arpPacket.Operation == ArpOperation.Response)
            {
                var victimIp = arpPacket.SenderProtocolAddress;
                var victimMac = arpPacket.SenderHardwareAddress;
                FoundDevice foundDev = new FoundDevice(victimIp, victimMac);
                lock (_syncLock)
                {
                    bool exists = false;
                    foreach (var d in FoundDevices)
                    {
                        if (d.Ip == victimIp)
                        {
                            exists = true;
                            break;
                        }
                    }

                    if (!exists)
                    {
                        FoundDevices.Add(foundDev);
                        DeviceFound.Invoke(foundDev);
                    }
                }
            }
        }
    }
}
