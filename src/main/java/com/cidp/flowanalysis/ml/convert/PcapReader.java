package com.cidp.flowanalysis.ml.convert;

import org.jnetpcap.PcapClosedException;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import static com.cidp.flowanalysis.ml.util.Utils.FILE_SEP;
import static com.cidp.flowanalysis.ml.util.Utils.FLOW_SUFFIX;

public class PcapReader {


    public static void readFile(String inputFile, String outPath,String label) {
        if(inputFile==null ||outPath==null ) {
            return;
        }

        //String fileName = FilenameUtils.getName(inputFile);
        Path p = Paths.get(inputFile);
        String fileName = p.getFileName().toString();

        if(!outPath.endsWith(FILE_SEP)){
            outPath += FILE_SEP;
        }

        File saveFileFullPath = new File(outPath+fileName+FLOW_SUFFIX);
        FlowGenerator flowGen = new FlowGenerator(true, 120000000L, 5000000L);
        flowGen.addFlowListener(new FlowListener(fileName,outPath));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

        System.out.println(String.format("Working on... %s",fileName));
        while(true) {
            try{
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                if(basicPacket !=null){
                    flowGen.addPacket(basicPacket,label);
                }
            }catch(PcapClosedException e){
                break;
            }
        }

        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(),label);

    }


    static class FlowListener implements FlowGenListener {

        private String fileName;

        private String outPath;

        private long cnt;

        public FlowListener(String fileName, String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow,String label) {

            String flowDump = flow.dumpFlowBasedFeaturesEx(label);
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            InsertCsvRow.insert(FlowFeature.getHeader(),flowStringList,outPath,fileName+ FLOW_SUFFIX);

            cnt++;

            String console = String.format("%s -> %d flows \r", fileName,cnt);

            System.out.print(console);
        }
    }
}
