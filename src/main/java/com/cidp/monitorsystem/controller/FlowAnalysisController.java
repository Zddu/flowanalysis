package com.cidp.monitorsystem.controller;

import com.cidp.monitorsystem.model.Algorithm;
import com.cidp.monitorsystem.model.EvaReasult;
import com.cidp.monitorsystem.model.RespBean;
import com.cidp.monitorsystem.service.dispservice.FlowAnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/flow")
public class FlowAnalysisController {
    @Autowired
    FlowAnalysisService flowAnalysisService;
    @PostMapping("/pcaptoarff")
    public RespBean upPcapFile(MultipartFile file) throws IOException {
        if (flowAnalysisService.pcapToarff(file)==1){
            return RespBean.ok("转换成功！");
        }else if (flowAnalysisService.pcapToarff(file)==-1){
            return RespBean.error("转换失败，IO异常!");
        }else {
            return RespBean.error("转换失败，格式不正确,请上传pcap数据包文件!");
        }
    }

    @GetMapping("/downarff")
    public void downArff(HttpServletResponse res) throws IOException {
        flowAnalysisService.downArff(res);
    }

    @PostMapping("/upprocessing")
    public RespBean upPcap(MultipartFile file) throws FileNotFoundException {
        if (flowAnalysisService.upProcess(file)==1){
            return RespBean.ok("上传成功！");
        }else if (flowAnalysisService.upProcess(file)==0){
            return RespBean.error("上传失败,格式不正确,请上传pcap文件!");
        }else {
            return RespBean.error("上传失败");
        }
    }

    @GetMapping("/tocsv")
    public RespBean toCSV(@RequestParam String label) throws FileNotFoundException {
        if (flowAnalysisService.toCSV(label)==1){
            return RespBean.ok("转换成功！");
        }else if (flowAnalysisService.toCSV(label)==-1){
            return RespBean.error("文件不存在，请先上传pcap文件！");
        }else {
            return RespBean.error("上传失败");
        }
    }

    @GetMapping("/downcsv")
    public void downcsv(HttpServletResponse res) throws IOException {
        flowAnalysisService.downCSV(res);
    }

    @PostMapping("/csvtoarff")
    public RespBean toarff(MultipartFile file){
        if (flowAnalysisService.toArff(file)==1){
            return RespBean.ok("转换成功！");
        }else if(flowAnalysisService.toArff(file)==0){
            return RespBean.error("文件流设置异常！");
        }else if(flowAnalysisService.toArff(file)==-1){
            return RespBean.error("获取数据集失败！");
        }else if(flowAnalysisService.toArff(file)==3){
            return RespBean.error("文件格式不正确,不是csv文件！");
        }else {
            return RespBean.error("设置选项失败!");
        }
    }

    @PostMapping("/uparffunlabel")
    public RespBean UpUnlabel( String body, MultipartFile file) throws FileNotFoundException {
        if (flowAnalysisService.UpUnlabel(body,file)==1){
            return RespBean.ok("上传成功！");
        }else if (flowAnalysisService.UpUnlabel(body,file)==0){
            return RespBean.error("上传失败,格式不正确,请上传pcap文件!");
        }else {
            return RespBean.error("上传失败");
        }
    }

    @GetMapping("/downarffunlabel")
    public void downUnlabel(HttpServletResponse res) throws IOException {
        flowAnalysisService.downUnlabel(res);
    }

    @GetMapping("/getalgs")
    public List<Algorithm> getAlgors(){
        return flowAnalysisService.getAllAlgs();
    }
    @GetMapping("/getchoicealgs")
    public void getChoice(@RequestParam String choice){
        flowAnalysisService.getChoice(choice);
    }

    @PostMapping("/updataset")
    public RespBean upDataSet(MultipartFile file){
        if (flowAnalysisService.upDataSet(file)==1){
            return RespBean.ok("上传成功");
        }else {
            return RespBean.error("上传失败！");
        }
    }
    @GetMapping("/start")
    public RespBean startTrain(){
        if (flowAnalysisService.start()==1){
            return RespBean.ok("训练成功!");
        }else if(flowAnalysisService.start()==0){
            return RespBean.error("训练失败，没有选择分类器!");
        }else {
            return RespBean.error("训练失败!");
        }
    }

    @GetMapping("/evaluation")
    public EvaReasult getResult(){
        return flowAnalysisService.getResult();
    }
}
