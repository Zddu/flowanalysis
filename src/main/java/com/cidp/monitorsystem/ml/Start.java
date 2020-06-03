package com.cidp.monitorsystem.ml;


import com.cidp.monitorsystem.ml.convert.PcapReader;
import org.jnetpcap.Pcap;
import java.util.Date;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.util.ArrayList;
import java.util.List;

public class Start {
    public static void main(String[] args) throws Exception {
        ex();
    }
    public static void convert(){
        PcapReader.readFile("C:\\Users\\Administrator\\Desktop\\app\\yahoo\\0__a1_out.pcap","C:\\Users\\Administrator\\Desktop\\1","123");
    }
    public void netCard() throws Exception {
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> ifs = new ArrayList<>();
        if(Pcap.findAllDevs(ifs, errbuf)!=Pcap.OK) {
            System.out.println("Error occured: " + errbuf.toString());
            throw new Exception(errbuf.toString());
        }
        System.out.println(ifs.get(2).getName());
    }

    public static void ex(){
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // 网卡list
        StringBuilder errbuf = new StringBuilder(); // 错误信息

        /***************************************************************************
         * 第一步获取系统网卡列表
         **************************************************************************/
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("不能获取网卡列表, 错误原因 %s", errbuf.toString());
            return;
        }

        System.out.println("找到的网卡:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description =
                    (device.getDescription() != null) ? device.getDescription()
                            : "描述不可得";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        PcapIf device = alldevs.get(2); // We know we have atleast 1 device
//        System.out.printf("\n选择 '%s' 在你操作之前:\n", (device.getDescription() != null) ? device.getDescription() : device.getName());

        /***************************************************************************
         * 第二步监听选择的网卡
         **************************************************************************/
        int snaplen = 64 * 1024;           // 不分割数据包
        int flags = Pcap.MODE_PROMISCUOUS; // 捕获所有
        int timeout = 10 * 1000;           // 10 seconds in millis
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("发生错误: "
                    + errbuf.toString());
            return;
        }

        /***************************************************************************
         * 第三步创造一个数据包处理器，这个处理器将接收来自loop的数据包
         **********************************************************************/
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {

                System.out.printf("接收的数据 %s 实际捕获长度=%-4d 原始长度=%-4d %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(),  // 实际捕获长度
                        packet.getCaptureHeader().wirelen(), // 原始长度
                        user                                 // 用户对象
                );
            }
        };

        /***************************************************************************
         * 第四 进入loop，并且告诉处理器捕获10个数据包
         **************************************************************************/
        pcap.loop(10, jpacketHandler, "jNetPcap rocks!");

        /***************************************************************************
         * 最后关闭资源
         **************************************************************************/
        pcap.close();
    }
}
