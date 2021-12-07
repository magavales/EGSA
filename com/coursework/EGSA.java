package com.coursework;
import java.io.*;
import java.security.*;
import java.math.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class EGSA {
    static Random rnd = new Random();
    static int max = 20;
    static int min = 2;
    static int numBits = (int) (Math.random() * ++max) + min;

    
    public static BigInteger pow(BigInteger base, BigInteger exponent) {
        BigInteger result = BigInteger.ONE;
        while (exponent.signum() > 0) {
            if (exponent.testBit(0)) result = result.multiply(base);
            base = base.multiply(base);
            exponent = exponent.shiftRight(1);
        }
        return result;
    }
    
    public static void writeFile(BigInteger key, String filename) {
        try(FileWriter writer = new FileWriter(filename, false))
        {

            writer.write(key.toString());
             
            writer.flush();
        }
        catch(IOException ex){
             
            System.out.println(ex.getMessage());
        }
    }

    public static void writeToEndFile(BigInteger a, BigInteger b, String filename) throws IOException {
        int sizeOfFile = (int)Files.size(Paths.get(filename));
        String signature = " " + "magavales" + " " + a.toString() + " " + b.toString() + " " + sizeOfFile + " " + "magavales";
        try {
            FileWriter writer = new FileWriter(filename, true);
            BufferedWriter bufferWriter = new BufferedWriter(writer);
            bufferWriter.write(signature);
            bufferWriter.close();

            File f = new File(filename);
            StringBuffer buff = new StringBuffer(f.getName());
            buff.append(".sig");
            f.renameTo(new File(buff.toString()));
        }
        catch (IOException e) {
            System.out.println(e);
        }
    }

    public static int countLines(File file) throws FileNotFoundException, IOException {
      FileInputStream fis = new FileInputStream(file);
      byte[] byteArray = new byte[(int)file.length()];
      fis.read(byteArray);
      String data = new String(byteArray);
      String[] stringArray = data.split("\r\n");
      fis.close();
      return stringArray.length;
    }

    static class IncorrectSignException extends Exception  {
        public IncorrectSignException(String message) {
            super(message);
        }
    }

    public static String readFile(String filename)  throws FileNotFoundException, IOException {
        File file = new File(filename);
        int lines = countLines(file);
        int count = 1;
        String result = "";
        FileReader fr = new FileReader(file);
        BufferedReader reader = new BufferedReader(fr);
        while (lines != count) {

            result = reader.readLine();
            count++;
        }
        reader.close();
        return result;
    }

    private static BigInteger gcd(BigInteger a, BigInteger b) {
        BigInteger t;
        while(b.compareTo(new BigInteger("0")) != 0){
            t = a;
            a = b;
            b = t.mod(b);
        }
        return a;
    }

    private static boolean relativelyPrime(BigInteger a, BigInteger b) {
        return gcd(a,b).compareTo(new BigInteger("1")) == 0;
    }

    private static ArrayList<BigInteger> xgcd(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO))
            return new ArrayList<BigInteger>(Arrays.asList(a, BigInteger.ONE, BigInteger.ZERO));
        else {
            ArrayList<BigInteger> arr = xgcd(b, a.mod(b));
            return new ArrayList<>(
                    Arrays.asList(arr.get(0), arr.get(2), arr.get(1).subtract(a.divide(b).multiply(arr.get(2)))));
        }
    }
    
    public static BigInteger comparisonSolution(BigInteger m, BigInteger a, BigInteger secretKey, BigInteger k, BigInteger p) {
        BigInteger temp = p.subtract(new BigInteger("1"));
        BigInteger b = BigInteger.ZERO;
        BigInteger reverseElement = BigInteger.ZERO;
        ArrayList<BigInteger> arr = xgcd(k, temp);
        if(relativelyPrime(k, temp) == true){
            if(k.multiply(arr.get(1)).mod(temp).compareTo(BigInteger.ONE) == 0){
                reverseElement = arr.get(1).mod(temp);
            }
            b = reverseElement.multiply(m.subtract(secretKey.multiply(a))).mod(temp);
        }
        
        return b;
    }

    public static String getKeys(String filename) throws FileNotFoundException, IOException{
        try(BufferedReader in = new BufferedReader(new FileReader(filename));) {
            String result = in.readLine();
            return result;
        }
        
    }

    public static String getFileSHA256(String filename) throws IOException, NoSuchAlgorithmException {
        File file = new File(filename);
        int sizeOfFile = (int) Files.size(Paths.get(filename));
        FileInputStream fis = new FileInputStream(file);
        byte[] bytes = SHA256.getHash(fis.readNBytes(sizeOfFile));
        fis.close();

        String s = SHA256.bytesToHex(bytes);
        System.out.println("Hash of first " + Integer.toString(sizeOfFile) + " bytes of "  + file.getName() + " = " + s);
        
        return s;
    }

    public static String getFileSHA256(String filename, int sizeOfFileSign) throws IOException, NoSuchAlgorithmException {
        File file = new File(filename);
        int sizeOfFile = (int) Files.size(Paths.get(filename));
        sizeOfFile = sizeOfFile - sizeOfFileSign;
        FileInputStream fis = new FileInputStream(file);
        byte[] bytes = SHA256.getHash(fis.readNBytes(sizeOfFile));
        fis.close();

        String s = SHA256.bytesToHex(bytes);
        System.out.println("Hash of first " + Integer.toString(sizeOfFile) + " bytes of "  + file.getName() + " = " + s);
        
        return s;
    }

    public static void generateKey(BigInteger secretKey, BigInteger openKey){        
        BigInteger p = BigInteger.probablePrime(1024, rnd);
        BigInteger g = BigInteger.probablePrime(512, rnd);
        secretKey = new BigInteger(numBits, rnd);
        while(true){
            if(p.compareTo(secretKey) > 0){
                break;
            }
            else{
                secretKey = new BigInteger(numBits, rnd);
            }
        }
        writeFile(secretKey, "secretkey.txt");
        openKey = g.modPow(secretKey, p);
        writeFile(openKey, "openkey.txt");
        writeFile(p, "p.txt");
        writeFile(g, "g.txt");
    }

    public static String getElemetSign(String signature) {
        String str_b = signature.substring(signature.indexOf(' ') + 1);
        String str_a = signature.replace (" " + str_b, "");

        return str_a;
    }

    public static void createSign(String filename, String secretKeyFile) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        try{
            BigInteger P = new BigInteger(getKeys("p.txt"));
            BigInteger G = new BigInteger(getKeys("g.txt"));
            BigInteger secretKey = new BigInteger(getKeys(secretKeyFile));
            BigInteger checksum = new BigInteger(getFileSHA256(filename), 16);
            BigInteger k;
            BigInteger temp;
            temp = P.subtract(new BigInteger("1"));
            while(true){
                k = new BigInteger(numBits, rnd);
                if(temp.compareTo(k) > 0 && relativelyPrime(k, temp) == true){
                    break;
                }
            }
            BigInteger a = G.modPow(k, P);
            BigInteger b = comparisonSolution(checksum, a, secretKey, k, P);
            writeToEndFile(a, b, filename);
        }
        catch (Exception e) {
            System.out.println("Something went wrong! The file could not be signed.");
            return;
        }

        System.out.println("The sign was successfully created!");
    }

    public static void checkSign(String filename, String openKeyFile) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        File file = new File(filename);
        try (RandomAccessFile raf = new RandomAccessFile(file, "rw");){
            BigInteger openKey = new BigInteger(getKeys(openKeyFile));

            int sizeOfFile = (int)Files.size(Paths.get(filename));
            if (sizeOfFile < 0  || sizeOfFile == 0) {
                throw new IncorrectSignException("Failed to detect sign ");
            }

            raf.seek(sizeOfFile - 9);
            byte[] personalSignature = new byte[9];
            raf.read(personalSignature);
            if(new String(personalSignature, "ASCII").equals("magavales") == false){
                throw new IncorrectSignException("Failed to find sign");
            }

            int count = 1;
            int countSpaces = 0;
            String result;

            while(true){
                raf.seek(sizeOfFile - 10 - count);
                byte [] buffer = new byte[sizeOfFile - 10 - count];
                raf.read(buffer);
                result = new String(buffer, "ASCII");
                for(int i = 0; i < result.length(); i++) {
                    if(Character.isWhitespace(result.charAt(i))) countSpaces++;
                }
                if(countSpaces == 2){
                    raf.seek(sizeOfFile - 10 - count + 1);
                    buffer = new byte[sizeOfFile - 10 - count + 1];
                    raf.read(buffer);
                    result = new String(buffer, "ASCII");
                    break;
                }
                else{
                    countSpaces = 0;
                    count++;
                }
            }
            String sizeOfFileOld = result.substring(result.indexOf(' ') + 1);
            sizeOfFileOld = result.replace (" " + sizeOfFileOld, "");
            int sizeOfFileSign = sizeOfFile - Integer.parseInt(sizeOfFileOld);

            String signature = "";
            if(sizeOfFile != sizeOfFileSign){
                raf.seek(sizeOfFile - sizeOfFileSign);
                byte [] buffer = new byte[sizeOfFile - sizeOfFileSign];
                raf.read(buffer);
                signature = new String(buffer, "ASCII");
            }
            else{
                signature = getKeys(filename);
            }

            countSpaces = 0;
            for(int i = 0; i < sizeOfFileSign; i++) {
                if(Character.isWhitespace(signature.charAt(i)))  countSpaces++;
            }
            String str;
            BigInteger checksum = new BigInteger(getFileSHA256(filename, sizeOfFileSign), 16);
            while(countSpaces != 3){
                str = signature.substring(signature.indexOf(' ') + 1);
                signature = str;
                countSpaces = 0;
                for(int i = 0; i < signature.length(); i++) {
                    if(Character.isWhitespace(signature.charAt(i))) countSpaces++;
                }
            }
            String str_a = getElemetSign(signature);
            signature = signature.substring(signature.indexOf(' ') + 1);
            String str_b = getElemetSign(signature);

            BigInteger P = new BigInteger(getKeys("p.txt"));
            BigInteger G = new BigInteger(getKeys("g.txt"));

            BigInteger a = new BigInteger(str_a);
            BigInteger b = new BigInteger(str_b);
            BigInteger one = openKey.modPow(a, P);
            BigInteger two = a.modPow(b, P);
            BigInteger A = one.multiply(two).mod(P);
            BigInteger B = G.modPow(checksum, P);

            raf.close();

            if(A.compareTo(B) == 0){
                System.out.print("The sign of file is right!\n");
            }
            else{
                System.out.print("Something went wrong!\n");
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

}
