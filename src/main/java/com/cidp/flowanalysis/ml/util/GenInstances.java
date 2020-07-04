package com.cidp.flowanalysis.ml.util;

import com.cidp.flowanalysis.ml.convert.*;
import org.jnetpcap.PcapClosedException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ArffLoader;
import weka.core.converters.ArffSaver;
import weka.core.converters.CSVLoader;
import weka.core.converters.DatabaseSaver;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@Component
public class GenInstances {
    @Value("${spring.datasource.url}")
    private String url;
    @Value("${spring.datasource.username}")
    private String username;
    @Value("${spring.datasource.password}")
    private String password;
    @Value("${savetable.name}")
    private String name;
    public  final String DATASETPATH = "C:\\Users\\Administrator\\Desktop\\1\\genarff.arff";

    public  Instances GenAttr(List<String> labels, String path, String label) throws IOException {
        FlowGenerator flowGen = new FlowGenerator(true, 120000000L, 5000000L);
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(path, readIP4, readIP6);
        while (true) {
            try {
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                if (basicPacket != null) {
                    flowGen.addPacket(basicPacket, label);
                }
            } catch (PcapClosedException e) {
                break;
            }
        }
        List<double[]> doubles = flowGen.dumpLabeledFlowInstances(80);

        ArrayList<Attribute> atts = new ArrayList<Attribute>();
        for (FlowFeature feature : FlowFeature.values()) {
            atts.add(new Attribute(feature.getAbbr()));
        }
        ArrayList<String> values = new ArrayList<String>();
        values.addAll(labels);
        atts.add(new Attribute("label", values));
        atts.remove(0);
        atts.remove(1);
        atts.remove(3);
        atts.remove(6);
        Instances rel_struct = new Instances("flow_analysis", atts, 0);
        rel_struct.setClassIndex(rel_struct.numAttributes() - 1);

        for (double[] aDouble : doubles) {
            double[] data = new double[atts.size()];
            for (int i = 0; i < aDouble.length; i++) {
                data[i] = aDouble[i];
            }
            data[80] = rel_struct.attribute(80).indexOfValue(label);
            Instance inst = new DenseInstance(1.0, data);
            rel_struct.add(inst);
        }

        return rel_struct;

    }

    public  void GenAttrNoLabel() throws IOException {
        FlowGenerator flowGen = new FlowGenerator(true, 120000000L, 5000000L);
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(DATASETPATH, readIP4, readIP6);
        while (true) {
            try {
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                if (basicPacket != null) {
                    flowGen.addPacket(basicPacket, "?");
                }
            } catch (PcapClosedException e) {
                break;
            }
        }
        List<double[]> doubles = flowGen.dumpLabeledFlowInstances(80);

        ArrayList<Attribute> atts = new ArrayList<Attribute>();
        for (FlowFeature feature : FlowFeature.values()) {
            atts.add(new Attribute(feature.getAbbr()));
        }
        atts.remove(0);
        atts.remove(1);
        atts.remove(3);
        atts.remove(6);
        Instances rel_struct = new Instances("flow_analysis", atts, 100);
        rel_struct.setClassIndex(rel_struct.numAttributes() - 1);

        for (double[] aDouble : doubles) {
            double[] data = new double[atts.size()];
            for (int i = 0; i < aDouble.length; i++) {
                data[i] = aDouble[i];
            }
            Instance inst = new DenseInstance(1.0, data);
            rel_struct.add(inst);
        }
        System.out.println(rel_struct);


        //保存生成的Instances实例
//        ArffSaver saver = new ArffSaver();
//        saver.setInstances(rel_struct);
//        saver.setFile(new File("C:\\Users\\Administrator\\Desktop\\1\\genarff.arff"));
//        saver.writeBatch();
    }

    public  void GenData() {
        FlowGenerator flowGen = new FlowGenerator(true, 120000000L, 5000000L);
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(DATASETPATH, readIP4, readIP6);
        while (true) {
            try {
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                if (basicPacket != null) {
//                    flowGen.addPacket(basicPacket);
                }
            } catch (PcapClosedException e) {
                break;
            }
        }
        flowGen.dumpLabeledFlowInstances(81);
    }

    public  Instances CsvToArff(File file) throws Exception {
        CSVLoader loader = new CSVLoader();
        loader.setSource(new FileInputStream(file));
        String[] options = new String[1];
        options[0] = "-H";
        loader.setOptions(options);
        ArffLoader loader1 = new ArffLoader();
        loader1.setFile(file);
        Instances dataSet = loader1.getDataSet();
        ArffSaver saver = new ArffSaver();
        saver.setInstances(dataSet);
        return saver.getInstances();
    }

    public void ToDataBase(Instances instances) throws Exception {
        DatabaseSaver databaseSaver = new DatabaseSaver();
        databaseSaver.setDestination(url, username, password);
        databaseSaver.setTableName(name);
        databaseSaver.setRelationForTableName(false);
        databaseSaver.setRetrieval(DatabaseSaver.INCREMENTAL);
        databaseSaver.setStructure(instances);
        for (int i = 0; i < instances.numInstances(); i++) {
            databaseSaver.writeIncremental(instances.instance(i));
        }
        databaseSaver.writeIncremental(null);
    }
}
