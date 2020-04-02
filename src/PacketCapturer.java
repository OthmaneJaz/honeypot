import java.util.ArrayList;
import java.util.Arrays;
//import java.util.List;
import java.util.Scanner;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.checksum.Checksum;
 
public class PacketCapturer {
 
    public static void main(String[] args) {
        try {
            // Will be filled with NICs (network interface card)
            ArrayList<PcapIf> alldevs = new ArrayList<PcapIf>();
 
            // For any error msgs
            StringBuilder errbuf = new StringBuilder();
 
            //Getting a list of devices
            int r = Pcap.findAllDevs(alldevs, errbuf);
            System.out.println(r);
            if (r != Pcap.OK) {
                System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
                return;
            }
 
            System.out.println("Network devices found:");
            int i = 0;
            for (PcapIf device : alldevs) {
                String description =
                        (device.getDescription() != null) ? device.getDescription()
                        : "No description available";
                System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
            }
            System.out.println("choose the one device from above list of devices");
            int ch = new Scanner(System.in).nextInt();
            PcapIf device = alldevs.get(ch);
 
            int snaplen = 64 * 1024;           // Capture all packets, no trucation
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
            int timeout = 10 * 1000;           // 10 seconds in millis
 
            //Open the selected device to capture packets
            Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
 
            if (pcap == null) {
                System.err.printf("Error while opening device for capture: "
                        + errbuf.toString());
                return;
            }
            System.out.println("device opened");
 
            //Create packet handler which will receive packets
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
                Arp arp = new Arp();
        		//Tcp tcp = new Tcp();
        		//Udp udp = new Udp();
        		Ip4 ip4 = new Ip4();
        		

                public void nextPacket(PcapPacket packet, String user) {
                    //Here i am capturing the ARP packets only (+TCP),you can capture any packet that you want by just changing the below if condition
                    //System.out.println("distinction des packets");

                	
                 
                	if (packet.hasHeader(arp)) {
                		System.out.println("--> arp packet detected");
                        System.out.println("Hardware type" + arp.hardwareType());
                        System.out.println("Protocol type" + arp.protocolType());
                        System.out.println("Packet:" + arp.getPacket());
                        System.out.println();
                    }//else {System.out.println("--> no arp packet detected");}
                    
                    if (packet.hasHeader(Tcp.ID) && packet.hasHeader(ip4)) {
                    		System.out.println("--> tcp packet detected");                    
                            final Tcp tcp = packet.getHeader(new Tcp());
                            System.out.println("Tcp Source Port :" + tcp.source());
                            System.out.println("Tcp Destination Port :" + tcp.destination()); 
                           
                            System.out.println("Ip4 Source :" + org.jnetpcap.packet.format.FormatUtils.ip((ip4.source())));  
                            System.out.println("Ip4 Destination  :" + org.jnetpcap.packet.format.FormatUtils.ip((ip4.destination())));  

                           // System.out.println(Arrays.toString(byteArray));
                            // org.jnetpcap.packet.format.FormatUtils.ip(sIP)
                                              	
            			}//else{System.out.println("--> no tcp packet detected");} 
                    
                    if (packet.hasHeader(Udp.ID) && packet.hasHeader(ip4)) {
                		System.out.println("--> udp packet detected");                    
                        final Udp udp = packet.getHeader(new Udp());
                        System.out.println("Udp Source Port :" + udp.source());
                        System.out.println("Udp Destination Port :" + udp.destination()); 
                       
                        System.out.println("Ip4 Source :" + org.jnetpcap.packet.format.FormatUtils.ip((ip4.source())));  
                        System.out.println("Ip4 Destination  :" + org.jnetpcap.packet.format.FormatUtils.ip((ip4.destination())));  

                       // System.out.println(Arrays.toString(byteArray));
                        // org.jnetpcap.packet.format.FormatUtils.ip(sIP)
                                          	
        			}//else{System.out.println("--> no udp packet detected");} 
                }

				
            };
            //we enter the loop and capture the 20 packets here.You can  capture any number of packets just by changing the first argument to pcap.loop() function below
            pcap.loop(20, jpacketHandler, "jnetpcap rocks!");
            //Close the pcap
            pcap.close();
        } catch (Exception ex) {
            System.out.println(ex);
        }
    }
}