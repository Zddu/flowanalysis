package com.cidp.flowanalysis.ml.convert;

import com.cidp.flowanalysis.mapper.InstancesMapper;
import com.cidp.flowanalysis.model.Feature;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.beans.PropertyChangeSupport;
import java.util.List;

@Component
public class RealCapture implements FlowGenListener {
    @Autowired
    InstancesMapper instancesMapper;
    private int snaplen = 64 * 1024;
    private int promiscous = Pcap.MODE_PROMISCUOUS;
    private int timeout = 60 * 1000;
    private Pcap pcap;
    private FlowGenerator flowGen = new FlowGenerator(true,120000000L, 5000000L);


    public void open(String device){
        this.pcap = Pcap.openLive(device,this.snaplen,this.promiscous,this.timeout,new StringBuilder());
    }

    public void start(){
        PcapPacketHandler<String> jpacketHandler = (packet, user) -> {
            PcapPacket permanent = new PcapPacket(JMemory.Type.POINTER);
            packet.transferStateAndDataTo(permanent);
            flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, true, false),"label");
        };

        pcap.loop(Pcap.DISPATCH_BUFFER_FULL, jpacketHandler, "");
    }

    public List<Feature> getBackFeatures() {
        List<Feature> doubles = flowGen.dumpLabeledFlowInstances();
        for (Feature aDouble : doubles) {
            System.out.println(aDouble.toString());
        }
        return doubles;
    }

    public List<Feature> stop(){
        pcap.breakloop();
        instancesMapper.insertInstances(flowGen.dumpLabeledFlowInstances());
        return  flowGen.dumpLabeledFlowInstances();
    }
    public int doInBackground(String device,int stopid) {

        FlowGenerator flowGen = new FlowGenerator(true,120000000L, 5000000L);
        flowGen.addFlowListener(this);
        int snaplen = 64 * 1024;//2048; // Truncate packet at this size
        int promiscous = Pcap.MODE_PROMISCUOUS;
        int timeout = 60 * 1000; // In milliseconds
        StringBuilder errbuf = new StringBuilder();

        Pcap pcap = Pcap.openLive(device, snaplen, promiscous, timeout, errbuf);

        if (stopid==0){
            System.out.println(2);
            pcap.breakloop();
        }
        if (pcap == null) {
            return -2;
        }
        PcapPacketHandler<String> jpacketHandler = (packet, user) -> {
            PcapPacket permanent = new PcapPacket(JMemory.Type.POINTER);
            packet.transferStateAndDataTo(permanent);
            System.out.println("TrafficFlowWorker:60L"+permanent);
            flowGen.addPacket(PacketReader.getBasicPacketInfo(permanent, true, false),"label");
        };
        List<double[]> doubles = flowGen.dumpLabeledFlowInstances(80);
        for (double[] aDouble : doubles) {
            for (int i = 0; i < aDouble.length; i++) {
                System.out.print(aDouble[i]+",");
            }
        }
        int ret = pcap.loop(Pcap.DISPATCH_BUFFER_FULL, jpacketHandler, device);
        System.out.println("ret:"+ret);
        return 1;
    }


    @Override
    public void onFlowGenerated(BasicFlow flow, String label) {
        new PropertyChangeSupport(this).firePropertyChange("flow",null,flow);
    }


}
