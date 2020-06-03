package com.cidp.monitorsystem.ml.util;

import com.cidp.monitorsystem.ml.convert.BasicFlow;
import com.cidp.monitorsystem.ml.convert.FlowGenListener;
import com.cidp.monitorsystem.ml.convert.FlowGenerator;
import com.cidp.monitorsystem.ml.convert.PacketReader;
import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.beans.PropertyChangeSupport;

public class RealGenFlow implements FlowGenListener {

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
