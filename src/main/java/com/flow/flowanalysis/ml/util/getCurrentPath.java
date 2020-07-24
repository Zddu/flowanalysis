package com.flow.flowanalysis.ml.util;

import org.springframework.util.ResourceUtils;

import java.io.FileNotFoundException;

public class getCurrentPath {
    public static String getPath() throws FileNotFoundException {
        String os = System.getProperties().getProperty("os.name");
        String path = null;
        if (os.startsWith("Windows")){
            path = ResourceUtils.getURL("classpath:").getPath();
        }else if (os.startsWith("Linux")){
            path = "/root/student/";
        }
        return path;
    }
}
