package com.cidp.monitorsystem.model;

import lombok.Data;

/**
 * echarts 图表插件 中饼状图的data数据格式
 * system表 各类型的数量
 * 二层交换机, 三层交换机, 路由器, 服务器
 */
@Data
public class SeriesData {
    private Integer value; //设备数量
    private String name;//设备名称
}
