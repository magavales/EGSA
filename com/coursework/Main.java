package com.coursework;
import java.io.*;
import java.security.*;
import java.math.*;



public class Main {
    public static void main(String[] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException {

        String filename = "";
        String secretKeyfile = "";
        String openKeyfile = "";

        String menu[] = {
            "Choose your action and remember, one day you will have to answer for your action and God may not be so merciful!\n",
            "Generate key: java -jar EGSA.jar <-generateKey>\n",
            "Create sign: java -jar EGSA.jar <-createSign> <filename for sign> <secretkey>\n",
            "Check sign: java -jar EGSA.jar <-checkSign> <filename for check> <openkey>\n",
        };
        


        switch (args[0]) {
            case "-help":
                for(String now : menu) {
                    System.out.print(now);
                }
                break;
            /*Генерация ключей */
            case "-generateKey":
                BigInteger secretKey = BigInteger.ZERO;
                BigInteger openKey = BigInteger.ZERO;
                EGSA.generateKey(secretKey, openKey);
                break;
            case "-createSign":
                filename = args[1];
                secretKeyfile = args[2];
                EGSA.createSign(filename, secretKeyfile);
                break;

            case "-checkSign":
                filename = args[1];
                openKeyfile = args[2];
                EGSA.checkSign(filename, openKeyfile);
                break;

            default:
                System.out.println("Cannot detect flag <-help, -generateKey, -createSign, -checkSign>");
                for(String now : menu) {
                    System.out.print(now);
                }
                break;
        }
        
        
    }
}
