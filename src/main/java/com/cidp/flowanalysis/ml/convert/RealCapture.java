package com.cidp.flowanalysis.ml.convert;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.springframework.stereotype.Component;

import java.beans.PropertyChangeSupport;
import java.security.Principal;

@Component
public class RealCapture implements FlowGenListener {



    public int doInBackground(String device,int stopid) {

        FlowGenerator flowGen = new FlowGenerator(true,120000000L, 5000000L);
        flowGen.addFlowListener(this);
        int snaplen = 64 * 1024;//2048; // Truncate packet at this size
        int promiscous = Pcap.MODE_PROMISCUOUS;
        int timeout = 60 * 1000; // In milliseconds
        StringBuilder errbuf = new StringBuilder();

        Pcap pcap = Pcap.openLive(device, snaplen, promiscous, timeout, errbuf);
        if (pcap == null) {
            return -2;
        }

        PcapPacketHandler<String> jpacketHandler = (packet, user) -> {
            PcapPacket permanent = new PcapPacket(JMemory.Type.POINTER);
            packet.transferStateAndDataTo(permanent);
            System.out.println("TrafficFlowWorker:60L"+permanent);
            flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, true, false),"label");
            if (stopid==0){
                pcap.breakloop();
            }
        };

        int ret = pcap.loop(Pcap.DISPATCH_BUFFER_FULL, jpacketHandler, device);
        System.out.println(ret);
        return 1;
    }


    @Override
    public void onFlowGenerated(BasicFlow flow, String label) {
        new PropertyChangeSupport(this).firePropertyChange("flow",null,flow);
    }
}
