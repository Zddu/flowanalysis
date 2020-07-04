package com.cidp.flowanalysis.ml.util;

import com.cidp.flowanalysis.ml.convert.BasicFlow;
import com.cidp.flowanalysis.ml.convert.FlowGenListener;
import com.cidp.flowanalysis.ml.convert.FlowGenerator;
import com.cidp.flowanalysis.ml.convert.PacketReader;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.beans.PropertyChangeSupport;
import java.util.ArrayList;
import java.util.List;

public class RealGenFlow implements FlowGenListener {

    public static void main(String[] args) {

        String s = new RealGenFlow().doInBackground(devname());
        System.out.println(s);
    }

    public static String devname() {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // 网卡list
        StringBuilder errbuf = new StringBuilder(); // 错误信息

        /***************************************************************************
         * 第一步获取系统网卡列表
         **************************************************************************/
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("不能获取网卡列表, 错误原因 %s", errbuf.toString());
        }

        System.out.println("找到的网卡:");

        int i = 0;
        for (PcapIf device : alldevs) {
            String description =
                    (device.getDescription() != null) ? device.getDescription()
                            : "描述不可得";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        PcapIf device = alldevs.get(2);
        return device.getName();
    }

        protected String doInBackground(String device) {

            FlowGenerator flowGen = new FlowGenerator(true,120000000L, 5000000L);
            flowGen.addFlowListener(this);
            int snaplen = 64 * 1024;//2048; // Truncate packet at this size
            int promiscous = Pcap.MODE_PROMISCUOUS;
            int timeout = 60 * 1000; // In milliseconds
            StringBuilder errbuf = new StringBuilder();

            Pcap pcap = Pcap.openLive(device, snaplen, promiscous, timeout, errbuf);
            if (pcap == null) {
                return String.format("open %s fail ->",device)+errbuf.toString();
            }

            PcapPacketHandler<String> jpacketHandler = (packet, user) -> {
                PcapPacket permanent = new PcapPacket(JMemory.Type.POINTER);
                packet.transferStateAndDataTo(permanent);
                System.out.println();
                flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, true, false),"unlabeled");
            };

            //FlowMgr.getInstance().setListenFlag(true);

            firePropertyChange("progress","open successfully","listening: "+device);
            int ret = pcap.loop(Pcap.DISPATCH_BUFFER_FULL, jpacketHandler, device);

            String str;
            switch (ret) {
                case 0:
                    str = "listening: " + device + " finished";
                    break;
                case -1:
                    str = "listening: " + device + " error";
                    break;
                case -2:
                    str = "stop listening: " + device;
                    break;
                default:
                    str = String.valueOf(ret);
            }

            return str;
        }

        private void firePropertyChange(String progress, String oldValue, String newValue) {
            if (oldValue == null || newValue == null || !oldValue.equals(newValue)) {
                new PropertyChangeSupport(this).firePropertyChange(progress,oldValue,newValue);
            }
        }

        @Override
        public void onFlowGenerated(BasicFlow flow, String label) {
            new PropertyChangeSupport(this).firePropertyChange("flow",null,flow);
        }
}
