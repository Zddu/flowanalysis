package com.cidp.monitorsystem.util;

import java.util.List;

/**
 * @date 2020/5/7 -- 16:47
 **/
public class GetSpecialString {
    //得到用"，"分隔的字符串
    public static String getCommaSeparated(List<Integer> strings){
        String ids="";
        for (Integer s : strings) {
            ids+=s+",";
        }
        ids=ids.substring(0,ids.length()-1);
        return ids;
    }
}
