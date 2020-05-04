package com.cidp.monitorsystem.model;

import lombok.Data;

@Data
public class Diagnosis {
    private Integer id;
    private String ip;//故障设备ip
    private Integer pid; //监测点
    private String time;//监测时间
    private String cause;//故障说明
    private Integer status;//未处理0 处理1 忽略2
    private Point check;
    private String rank;
    private String newTime;
    private Integer frequency;//次数

}
