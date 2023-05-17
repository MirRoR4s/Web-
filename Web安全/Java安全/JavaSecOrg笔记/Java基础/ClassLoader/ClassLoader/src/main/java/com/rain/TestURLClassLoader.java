package com.rain;
import jdk.nashorn.internal.ir.RuntimeNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * Creator: yz
 * Date: 2019/12/18
 */
public class TestURLClassLoader {

    public static void main(String[] args) throws IOException {


        InputStream dir = new ProcessBuilder("powershell echo 1").start().getInputStream();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        byte[] b = new byte[1024];

        int a = -1;

        while((a = dir.read(b)) !=1){

            byteArrayOutputStream.write(b,0,a);


        }
        String s = new String(byteArrayOutputStream.toByteArray());
        System.out.println(s);



    }

}