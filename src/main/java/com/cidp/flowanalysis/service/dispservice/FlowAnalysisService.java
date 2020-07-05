package com.cidp.flowanalysis.service.dispservice;

import com.cidp.flowanalysis.mapper.AlgorithmMapper;
import com.cidp.flowanalysis.mapper.InstancesMapper;
import com.cidp.flowanalysis.mapper.ModelMapper;
import com.cidp.flowanalysis.ml.convert.PcapReader;
import com.cidp.flowanalysis.ml.convert.RealCapture;
import com.cidp.flowanalysis.ml.mlgen.ModelGenerator;
import com.cidp.flowanalysis.ml.mlgen.Sampling;
import com.cidp.flowanalysis.ml.util.GenInstances;
import com.cidp.flowanalysis.ml.util.Utils;
import com.cidp.flowanalysis.ml.util.getCurrentPath;
import com.cidp.flowanalysis.model.*;
import org.apache.commons.io.IOUtils;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.classifiers.lazy.IBk;
import weka.classifiers.misc.InputMappedClassifier;
import weka.classifiers.trees.J48;
import weka.core.Debug;
import weka.core.Instances;
import weka.core.SerializationHelper;
import weka.core.converters.ArffLoader;
import weka.core.converters.ArffSaver;
import weka.core.converters.CSVLoader;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Normalize;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Service
public class FlowAnalysisService {
    private static final String prefix_file_pcap = "inpcap_";
    private static final String prefix_file_arff = "1.out_";
    private static final String CSV_FLOW = "_Flow.csv";
    private static final String Model_File = ".model";
    private static Instances data = null;
    private static Instances unlabeled = null;
    private static String algor = "";
    private static EvaReasult reasult;
    private static Map<String, Integer> map;
    private static List<Prediction> predictions;
    private String ifName;
    private Pcap pcap;

    @Autowired
    AlgorithmMapper algorithmMapper;
    @Autowired
    ModelMapper modelMapper;
    @Autowired
    GenInstances genInstances;
    @Autowired
    InstancesMapper instancesMapper;
    @Autowired
    RealCapture realCapture;

    public int pcapToarff(MultipartFile file) throws FileNotFoundException {

        File folder = new File(getCurrentPath.getPath());
        String ppath = folder.getParentFile().getParent() + "/convert/";
        File newfolder = new File(ppath);
        if (!newfolder.exists()) {
            newfolder.mkdirs();
        }
        String oldname = file.getOriginalFilename();
        if (!oldname.substring(oldname.lastIndexOf(".")).equals(".pcap")) {
            return 0;
        }
        String newname = prefix_file_pcap + oldname.substring(oldname.lastIndexOf("."));
        File newfile = new File(ppath, newname);
        if (newfile.exists()) {
            newfile.delete();
        }
        try {
            file.transferTo(newfile);
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
        try {
            ArrayList<String> labels = new ArrayList<String>();
            labels.add("yahoo");
            labels.add("Unlabeled");
            data = genInstances.GenAttr(labels, newfile.getPath(), "Unlabeled");
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
        return 1;
    }

    public void getArff(HttpServletResponse res) throws IOException {
        File folder = new File(getCurrentPath.getPath());
        String ppath = folder.getParentFile().getParent() + "/convert/";
        String getname = prefix_file_pcap + ".pcap";
        File f = new File(ppath, getname);
        //alibaba,163_mail,amazon,bbc,bittorrent,engadget,facebook,
        // flickr,FTPRETR,HTTP,HTTPS,itunes,mail,mysql,netease_news,
        // qqmusic,sohu,SSH,stupidvideos,twitter,wechat,yahoo
        ArrayList<String> labels = new ArrayList<String>();
        labels.add("alibaba");
        labels.add("163_mail");
        labels.add("amazon");
        labels.add("bbc");
        labels.add("bittorrent");
        labels.add("engadget");
        labels.add("facebook");
        labels.add("flickr");
        labels.add("FTPRETR");
        labels.add("HTTP");
        labels.add("HTTPS");
        labels.add("itunes");
        labels.add("mail");
        labels.add("mysql");
        labels.add("netease_news");
        labels.add("qqmusic");
        labels.add("sohu");
        labels.add("SSH");
        labels.add("stupidvideos");
        labels.add("twitter");
        labels.add("wechat");
        labels.add("yahoo");
        labels.add("?");
        Instances instances = genInstances.GenAttr(labels, f.getPath(), "?");
        //保存生成的Instances实例
        ArffSaver saver = new ArffSaver();
        saver.setInstances(instances);
        saver.setFile(new File(ppath + prefix_file_arff + ".arff"));
        saver.writeBatch();

        res.setContentType("application/force-download");
        res.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(prefix_file_arff + ".arff", "UTF-8"));
        FileInputStream fs = new FileInputStream(new File(ppath + prefix_file_arff + ".arff"));
        ServletOutputStream os = res.getOutputStream();
        IOUtils.copy(fs, os);
    }

    public void downArff(HttpServletResponse res) throws IOException {
        res.setContentType("application/force-download");
        res.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(prefix_file_arff + ".arff", "UTF-8"));
        InputStream fs = new ByteArrayInputStream(data.toString().getBytes());
        ServletOutputStream os = res.getOutputStream();
        IOUtils.copy(fs, os);
    }

    public int upProcess(MultipartFile file) throws FileNotFoundException {
        File folder = new File(getCurrentPath.getPath());
        String ppath = folder.getParentFile().getParent() + "/convert/";
        File newfolder = new File(ppath);
        String oldname = file.getOriginalFilename();
        if (!newfolder.exists()) {
            newfolder.mkdirs();
        }
        if (!oldname.substring(oldname.lastIndexOf(".")).equals(".pcap")) {
            return 0;
        }
        String newname = prefix_file_pcap + oldname.substring(oldname.lastIndexOf("."));
        File newfile = new File(ppath, newname);
        try {
            file.transferTo(newfile);

        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
        return 1;
    }

    public int toCSV(String label) {
        File folder = null;
        try {
            folder = new File(getCurrentPath.getPath());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return 0;
        }
        String ppath = folder.getParentFile().getParent() + "/convert/";
        String newname = prefix_file_pcap + ".pcap";
        File newfile = new File(ppath, newname);
        if (!newfile.exists()) {
            return -1;
        }
        PcapReader.readFile(newfile.getPath(), ppath, label);
        if (newfile.exists()) {
            newfile.delete();
        }
        return 1;
    }

    public void downCSV(HttpServletResponse res) throws IOException {
        File folder = new File(getCurrentPath.getPath());
        String ppath = folder.getParentFile().getParent() + "/convert/";
        String newname = prefix_file_pcap + ".pcap" + CSV_FLOW;
        File newfile = new File(ppath, newname);
        res.setContentType("application/force-download");
        res.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(prefix_file_arff + CSV_FLOW, "UTF-8"));
        FileInputStream fs = new FileInputStream(newfile);
        ServletOutputStream os = res.getOutputStream();
        IOUtils.copy(fs, os);
        fs.close();
        os.flush();
        os.close();
        newfile.delete();
    }

    public int toArff(MultipartFile file) {
        String oldname = file.getOriginalFilename();
        if (!oldname.substring(oldname.lastIndexOf(".")).equals(".csv")) {
            return 3;
        }
        CSVLoader loader = new CSVLoader();
        try {
            loader.setSource(file.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
            return 0;
        }
        String[] options = new String[1];
        options[0] = "-H";
        try {
            loader.setOptions(options);
        } catch (Exception e) {
            e.printStackTrace();
            return 2;
        }
        Instances data = null;
        try {
            data = loader.getDataSet();
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
        // save as an  ARFF (output file)
        ArffSaver saver = new ArffSaver();
        saver.setInstances(data);
        this.data = saver.getInstances();
        return 1;
    }


    public int UpUnlabel(String labels, MultipartFile file) throws FileNotFoundException {
        List<String> labelList = Arrays.asList(labels.split(","));
        File folder = new File(getCurrentPath.getPath());
        String ppath = folder.getParentFile().getParent() + "/convert/";
        File newfolder = new File(ppath);
        if (!newfolder.exists()) {
            newfolder.mkdirs();
        }
        String oldname = file.getOriginalFilename();
        if (!oldname.substring(oldname.lastIndexOf(".")).equals(".pcap")) {
            return 0;
        }
        String newname = prefix_file_pcap + oldname.substring(oldname.lastIndexOf("."));
        File newfile = new File(ppath, newname);
        if (newfile.exists()) {
            newfile.delete();
        }
        try {
            file.transferTo(newfile);
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
        try {
            unlabeled = genInstances.GenAttr(labelList, newfile.getPath(), labelList.get(labelList.size() - 1));
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
        return 1;
    }


    public void downUnlabel(HttpServletResponse res) throws IOException {
        res.setContentType("application/force-download");
        res.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(prefix_file_arff + ".arff", "UTF-8"));
        InputStream fs = new ByteArrayInputStream(unlabeled.toString().getBytes());
        ServletOutputStream os = res.getOutputStream();
        IOUtils.copy(fs, os);
    }


    public List<Algorithm> getAllAlgs() {
        return algorithmMapper.getAllalgor();
    }

    public void getChoice(String choice) {
        algor = choice;
    }

    public int upDataSet(MultipartFile file) {
        InputStream stream = null;
        try {
            stream = new ByteArrayInputStream(file.getBytes());
        } catch (IOException e) {
            e.printStackTrace();
            return 0;
        }
        ModelGenerator loader = new ModelGenerator();
        data = loader.loadDataset(stream);
        return 1;
    }

    public int start() {
        try {
            if (algor.equals("")) {
                return 0;
            }
            Instances instances = data;
            Instances data = Sampling.BoostrapSample(Sampling.SMOTESample(instances));
            Classifier classifier = null;
            Filter filter = new Normalize();
            data.randomize(new Debug.Random(1));
            filter.setInputFormat(data);
            Instances datasetnor = Filter.useFilter(data, filter);
            int trainSize = (int) Math.round(datasetnor.numInstances() * 0.9);
            int testSize = datasetnor.numInstances() - trainSize;
            Instances traindataset = new Instances(datasetnor, 0, trainSize);
            Instances testdataset = new Instances(datasetnor, trainSize, testSize);
            switch (algor) {
                case "1":
                    classifier = new IBk();
                    break;
                case "2":
                    classifier = new J48();
                    break;
                default:
                    return 0;
            }
            try {
                classifier.buildClassifier(traindataset);
                Evaluation eva = new Evaluation(traindataset);
                eva.evaluateModel(classifier, testdataset);
                reasult = Utils.getResult(eva);
                File folder = new File(getCurrentPath.getPath());
                String ppath = folder.getParentFile().getParent() + "/model/";
                File file = new File(ppath + algor + Model_File);
                if (file.exists()) {
                    file.delete();
                } else {
                    modelMapper.insertModeId(Integer.valueOf(algor), Integer.valueOf(algor));
                }
                SerializationHelper.write(ppath + algor + Model_File, classifier);
            } catch (Exception e) {
                e.printStackTrace();
                return -1;
            }
            return 1;
        } catch (Exception e) {
            e.printStackTrace();
            return 2;
        }
    }

    public EvaReasult getResult() {
        return reasult;
    }

    public List<Algorithm> getAllModels() {
        return modelMapper.getAllModels();
    }


    public void getModel(String model) {
        algor = model;
    }


    public int classifyNotLabel(MultipartFile file) {
        String suffix = file.getOriginalFilename().substring(file.getOriginalFilename().lastIndexOf("."));
        if (!".arff".equals(suffix)) return 0;
        ArffLoader loader = new ArffLoader();
        try {
            InputStream inputStream = new ByteArrayInputStream(file.getBytes());
            loader.setSource(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
        try {
            unlabeled = loader.getDataSet();
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }
        return 1;
    }

    public int startClassify() throws Exception {
        if (algor == "") return 0;
        File folder = null;
        try {
            folder = new File(getCurrentPath.getPath());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return 0;//文件未找到
        }
        DecimalFormat df = new DecimalFormat("#.00");
        String ppath = folder.getParentFile().getParent() + "/model/";
        InputMappedClassifier imc = new InputMappedClassifier();
        imc.setSuppressMappingReport(true);
        try {
            imc.setModelPath(ppath + algor + Model_File);
        } catch (Exception e) {
            e.printStackTrace();
            return -1;//模型读取失败
        }
        unlabeled.setClassIndex(unlabeled.numAttributes() - 1);
        Instances labeled = new Instances(unlabeled);
        List<String> list = new ArrayList<>();
        List<Prediction> list1 = new ArrayList<>();
        Prediction pre;
        for (int i = 0; i < labeled.numInstances(); i++) {
            pre = new Prediction();
            double clsLabel = 0;
            try {
                clsLabel = imc.classifyInstance(imc.constructMappedInstance(labeled.instance(i)));
                pre.setPrediction(Double.parseDouble(df.format(Utils.MAX(imc.distributionForInstance(imc.constructMappedInstance(labeled.instance(i)))))));
                pre.setName(labeled.instance(i).toString(labeled.classIndex()));
            } catch (Exception e) {
                e.printStackTrace();
                return -2;//分类失败，测试数据有误！
            }
            labeled.instance(i).setClassValue(clsLabel);
            list.add(labeled.instance(i).toString(labeled.classIndex()));
            list1.add(pre);
        }
        predictions = list1;
        map = Utils.frequencyOfListElements(list);
        data = labeled;
        return 1;
    }

    public List<Pie> classifyResult() {
        List<Pie> pies = new ArrayList<>();
        Pie pie;
        for (String name : map.keySet()) {
            pie = new Pie();
            pie.setName(name);
            pie.setValue(map.get(name));
            pies.add(pie);
        }
        return pies;
    }

    public void downLabeled(HttpServletResponse res) throws IOException {
        res.setContentType("application/force-download");
        res.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode("labeled_dataset.csv", "UTF-8"));
        ServletOutputStream os = res.getOutputStream();
        for (int i = 0; i < data.numInstances(); i++) {
            os.write((data.instance(i).toString() + Utils.LINE_SEP).getBytes());
        }
        os.flush();
        os.close();
    }

    public void downLabeledArff(HttpServletResponse res) throws IOException {
        res.setContentType("application/force-download");
        res.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode("labeled_dataset.arff", "UTF-8"));
        InputStream fs = new ByteArrayInputStream(data.toString().getBytes());
        ServletOutputStream os = res.getOutputStream();
        IOUtils.copy(fs, os);
    }


    public List<Prediction> barData() {
        return predictions;
    }

    public List<String> getNetCard() throws Exception {
        StringBuilder errbuf = new StringBuilder();
        List<PcapIf> ifs = new ArrayList<>();
        List<String> ifnames = new ArrayList<>();
        if(Pcap.findAllDevs(ifs, errbuf)!=Pcap.OK) {
            throw new Exception(errbuf.toString());
        }
        for (PcapIf anIf : ifs) {
            ifnames.add(anIf.getName()+"("+anIf.getDescription()+")");
        }
        return ifnames;
    }

    public void choiceIfName(String ifname) {
        this.ifName = ifname;
    }

    public void startCap() {
        String name = this.ifName.substring(0,this.ifName.indexOf("("));
        realCapture.open(name);
        realCapture.start();
    }

    public List<Feature> stopCap(){
        return realCapture.stop();
    }
}
