package com.cidp.flowanalysis.ml.util;

import com.cidp.flowanalysis.model.EvaReasult;
import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import weka.classifiers.Evaluation;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Utils {
    protected static final Logger logger = LoggerFactory.getLogger(Utils.class);
    public static final String FILE_SEP = System.getProperty("file.separator");// /
    public static final String LINE_SEP = System.lineSeparator();//换行符
    private final static String PCAP = "application/vnd.tcpdump.pcap";
    public static final String FLOW_SUFFIX = "_Flow.csv";


    private static boolean isPcapFile(String contentType) {

        return PCAP.equalsIgnoreCase(contentType);
    }
    public static int MAX(int[] arr) {
        return Arrays.stream(arr).max().getAsInt();
    }

    public static double MAX(double[] arr) {
        return Arrays.stream(arr).max().getAsDouble();
    }

    public static EvaReasult getResult(Evaluation eva) throws Exception {
        EvaReasult er = new EvaReasult();
        er.setCorrect(eva.correct());
        er.setIncorrect(eva.incorrect());
        er.setKappa(eva.kappa());
        er.setMeanAbsoluteError(eva.meanAbsoluteError());
        er.setRootMeanSquaredError(eva.rootMeanSquaredError());
        er.setRootRelativeSquaredError(eva.rootRelativeSquaredError());
        er.setTotalNumberOfInstances(eva.numInstances());
        er.setAvgCost(eva.avgCost());
        er.setPctCorrect(eva.pctCorrect());
        er.setPctUnclassified(eva.pctUnclassified());
        er.setRelativeAbsoluteError(eva.relativeAbsoluteError());
        er.setRootMeanPriorSquaredError(eva.rootMeanPriorSquaredError());
        er.setErrorRate(eva.errorRate());
        er.setWeightedRecall(eva.weightedRecall());
        er.setCorrect(1-eva.errorRate());
        return er;
    }
    public static boolean isPcapFile(File file) {

        if (file == null) {
            return false;
        }

        try {

            //Files.probeContentType returns null on Windows
            /*Path filePath = Paths.get(file.getPath());
            contentType = Files.probeContentType(filePath);*/

            return isPcapFile(new Tika().detect(file));

        } catch (IOException e) {
            logger.debug(e.getMessage());
        }

        return false;
    }

    public static boolean isPcapFile(InputStream stream) {

        if (stream == null) {
            return false;
        }

        try {
            return isPcapFile(new Tika().detect(stream));
        } catch (IOException e) {
            logger.debug(e.getMessage());
        }

        return false;
    }

    public static long countLines(String fileName) {
        File file =new File(fileName);
        int linenumber = 0;
        FileReader fr;
        LineNumberReader lnr = null;
        try {
            fr = new FileReader(file);
            lnr = new LineNumberReader(fr);

            while (lnr.readLine() != null){
                linenumber++;
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {

            if (lnr != null) {

                try {
                    lnr.close();
                } catch (IOException e) {
                    logger.debug(e.getMessage());
                }
            }
        }
        return linenumber;
    }

    public static Map<String,Integer> frequencyOfListElements( List<String> items ) {
        if (items == null || items.size() == 0) return null;
        Map<String, Integer> map = new HashMap<String, Integer>();
        for (String temp : items) {
            Integer count = map.get(temp);
            map.put(temp, (count == null) ? 1 : count + 1);
        }
        return map;
    }

}
