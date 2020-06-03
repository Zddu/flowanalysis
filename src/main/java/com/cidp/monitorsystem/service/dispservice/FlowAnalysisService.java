package com.cidp.monitorsystem.service.dispservice;

import com.cidp.monitorsystem.ml.convert.PcapReader;
import com.cidp.monitorsystem.ml.util.GenInstances;
import com.cidp.monitorsystem.ml.util.getCurrentPath;
import org.apache.commons.io.IOUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import weka.core.Instances;
import weka.core.converters.ArffSaver;
import weka.core.converters.CSVLoader;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class FlowAnalysisService {
    private static final String prefix_file_pcap = "inpcap_";
    private static final String prefix_file_arff = "1.out_";
    private static final String CSV_FLOW = "_Flow.csv";
    public static Instances data = null;
    public static Instances unlabeled = null;

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
            labels.add("Unlabeled");
            data = GenInstances.GenAttr(labels, newfile.getPath(), "Unlabeled");
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
        Instances instances = GenInstances.GenAttr(labels, f.getPath(), "?");
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
        if (!newfile.exists()){
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

    public int toArff(MultipartFile file)  {
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
        String [] options = new String[1];
        options[0]="-H";
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


    public int UpUnlabel(String labels , MultipartFile file) throws FileNotFoundException {
        List<String> labelList = Arrays.asList(labels .split("%"));
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
            unlabeled = GenInstances.GenAttr(labelList, newfile.getPath(), labelList.get(labelList.size()-1));
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
}
