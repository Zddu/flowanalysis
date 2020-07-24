package com.flow.flowanalysis.controller;

import com.flow.flowanalysis.model.*;
import com.flow.flowanalysis.service.dispservice.FlowAnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;

/**
 * 算法分析
 */
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

    @GetMapping("/getmodels")
    public List<Algorithm> getAllModels(){
        return flowAnalysisService.getAllModels();
    }
    @GetMapping("/choicemodel")
    public void choiceModel(@RequestParam String model){
        flowAnalysisService.getModel(model);
    }

    @PostMapping("/classifynot")
    public RespBean classifyNotLabel(MultipartFile file){
        if ( flowAnalysisService.classifyNotLabel(file)==1){
            return RespBean.ok("上传成功！");
        }else if (flowAnalysisService.classifyNotLabel(file)==0){
            return RespBean.error("上传失败，文件格式不正确!");
        }else {
            return RespBean.error("IO异常,上传失败！");
        }
    }

    @GetMapping("/startclassify")
    public RespBean startClassify() throws Exception {
        if (flowAnalysisService.startClassify()==1){
            return RespBean.ok("分类完成！");
        }else if (flowAnalysisService.startClassify()==0){
            return RespBean.error("文件未找到！");
        }else if (flowAnalysisService.startClassify()==-1){
            return RespBean.error("模型读取失败！");
        }else if (flowAnalysisService.startClassify()==-2){
            return RespBean.error("分类失败，测试数据有误！");
        }else {
            return RespBean.error("数据库异常！");
        }
    }
    @GetMapping("/classifyresult")
    public List<Pie> classifyResult(){
        return flowAnalysisService.classifyResult();
    }

    @GetMapping("/downlabeled")
    public void downLabeled(HttpServletResponse res) throws IOException {
        flowAnalysisService.downLabeled(res);
    }
    @GetMapping("/downlabeledarff")
    public void downLabeledArff(HttpServletResponse response) throws IOException {
        flowAnalysisService.downLabeledArff(response);
    }

    @GetMapping("/bardata")
    public List<Prediction> barData(){
        return flowAnalysisService.barData();
    }

    @GetMapping("/getnetcard")
    public List<String> getNetCard() throws Exception {
        return flowAnalysisService.getNetCard();
    }
    @GetMapping("/choiceif")
    public void choiceifName(@RequestParam String ifname){
        flowAnalysisService.choiceIfName(ifname);
    }

    @GetMapping("/startcap")
    public void startCap(){
        flowAnalysisService.startCap();
    }

    @GetMapping("/stopcap")
    public RespBean stopCap(){
        return RespBean.ok("停止成功", flowAnalysisService.stopCap());
    }

    @GetMapping("/showfeat")
    public List<Feature> showFeat(){
        return flowAnalysisService.showFeat();
    }

    @GetMapping("/startanalysis")
    public RespBean startAnalysis() throws IOException {
        if (flowAnalysisService.fromDataBase()==1){
            return RespBean.ok("分类完成！");
        }else if (flowAnalysisService.fromDataBase()==0){
            return RespBean.error("文件未找到！");
        }else if (flowAnalysisService.fromDataBase()==-1){
            return RespBean.error("模型读取失败！");
        }else if (flowAnalysisService.fromDataBase()==-2){
            return RespBean.error("分类失败，测试数据有误！");
        }else {
            return RespBean.error("数据库异常！");
        }
    }
}
