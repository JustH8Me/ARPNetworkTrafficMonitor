using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ArpTrafficMonitor
{
    internal class FoundDevice
    {
        public IPAddress Ip { get; private set; }
        public PhysicalAddress Mac { get; private set; }
        public bool IsBlocked { get; set; } = false;

        //счетчики Накапливаем
        public long UploadTotal { get; set; }
        public long DownloadTotal { get; set; }

        // для расчета скорости предыдущие значения
        public long PrevUpload { get; set; }
        public long PrevDownload { get; set; }

        //текущая скорость в байтах
        public double SpeedUp { get; set; }
        public double SpeedDown { get; set; }
        public byte[] MacBytes { get; private set; }
        public FoundDevice(IPAddress ip, PhysicalAddress mac)
        {
            Ip = ip;
            Mac = mac;
            MacBytes = mac.GetAddressBytes();
        }

        //логика 
        public void CalculateSpeed()
        {
            SpeedUp = UploadTotal - PrevUpload;
            SpeedDown = DownloadTotal - PrevDownload;

            PrevUpload = UploadTotal;
            PrevDownload = DownloadTotal;
        }
    }
}
