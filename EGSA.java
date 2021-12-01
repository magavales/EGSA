
import java.io.*;
import java.security.*;
import java.math.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

public class EGSA {
    static Random rnd = new Random();
    static BigInteger p = BigInteger.probablePrime(1024, rnd);
    static BigInteger g = BigInteger.probablePrime(512, rnd);
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

    public static void writeToEndFile(BigInteger a, BigInteger b, String filename) {
        String signature = " " + "magavales" + " " + a.toString() + " " + b.toString();
        try {
            FileWriter writer = new FileWriter(filename, true);
            BufferedWriter bufferWriter = new BufferedWriter(writer);
            bufferWriter.write(signature);
            bufferWriter.close();
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

    public static String readFile(String filename)  throws FileNotFoundException, IOException {
        File file = new File(filename);
        int lines = countLines(file);
        int count = 1;
        String result = "";
        FileReader fr = new FileReader(file);
        BufferedReader reader = new BufferedReader(fr);
        String line = reader.readLine();
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

    public static String getFileSHA256(String filename, String signature) throws IOException, NoSuchAlgorithmException {
        File file = new File(filename);
        int sizeOfFile = (int) Files.size(Paths.get(filename));
        sizeOfFile = sizeOfFile - signature.length();
        FileInputStream fis = new FileInputStream(file);
        byte[] bytes = SHA256.getHash(fis.readNBytes(sizeOfFile));
        fis.close();

        String s = SHA256.bytesToHex(bytes);
        System.out.println("Hash of first " + Integer.toString(sizeOfFile) + " bytes of "  + file.getName() + " = " + s);
        
        return s;
    }

    public static void generateKey(BigInteger secretKey, BigInteger openKey){
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
    }

    public static void createSign(String filename, String secretKeyFile) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        BigInteger secretKey = new BigInteger(getKeys(secretKeyFile));
        BigInteger checksum = new BigInteger(getFileSHA256(filename), 16);
        BigInteger k;
        BigInteger temp;
        temp = p.subtract(new BigInteger("1"));
        while(true){
            k = new BigInteger(numBits, rnd);
            if(temp.compareTo(k) > 0 && relativelyPrime(k, temp) == true){
                System.out.println("Good job!");
                break;
            }
        }
        BigInteger a = g.modPow(k, p);
        BigInteger b = comparisonSolution(checksum, a, secretKey, k, p);
        writeToEndFile(a, b, filename);
    }

    public static void checkSign(String filename, String openKeyFile) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        BigInteger openKey = new BigInteger(getKeys(openKeyFile));
        String signature = readFile(filename);
        int count = 0;
        for(int i = 0; i < signature.length(); i++) {
            if(Character.isWhitespace(signature.charAt(i))) count++;
        }
        String str;
        BigInteger checksum = BigInteger.ZERO;
        while(count != 1){
            str = signature.substring(signature.indexOf(' ') + 1);
            signature = str;
            count = 0;
            for(int i = 0; i < signature.length(); i++) {
                if(Character.isWhitespace(signature.charAt(i))) count++;
            }
            if(count == 2){                
                checksum = new BigInteger(getFileSHA256(filename, " " + signature), 16);
            }
        }
        String str_b = signature.substring(signature.indexOf(' ') + 1);
        String str_a = signature.replace (" " + str_b, "");
        BigInteger a = new BigInteger(str_a);
        BigInteger b = new BigInteger(str_b);
        BigInteger one = openKey.modPow(a, p);
        BigInteger two = a.modPow(b, p);
        BigInteger A = one.multiply(two).mod(p);
        BigInteger B = g.modPow(checksum, p);
        if(A.compareTo(B) == 0){
            System.out.print("The sign of file is right!\n");
        }
    }

    public static void main(String[] args) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        String menu[] = {
            "Choose your action and remember, one day you will have to answer for your action and God may not be so merciful!\n",
            "Generate key: keyword <generateKey>\n",
            "Create sign: keyword <createSign>\n",
            "Check sign: keyword <checkSign>\n",
            "Qiut from program: keyword <quit>\n"
        };
        
        boolean condition = true;

        while(condition == true){
            for(String now : menu) {
                System.out.print(now);
            }

            Scanner in = new Scanner(System.in);
            String string = in.nextLine();

            switch (string) {
                /*Генерация ключей */
                case "generateKey":
                    BigInteger secretKey = BigInteger.ZERO;
                    BigInteger openKey = BigInteger.ZERO;
                    generateKey(secretKey, openKey);
                    break;
                case "createSign":
                    in = new Scanner(System.in);
                    System.out.print("Input a name file, for which you want to create sign: ");
                    String filename = in.nextLine();
                    System.out.print("Input a name file with secret key: ");
                    String secretKeyfile = in.nextLine();
                    createSign(filename, secretKeyfile);
                    break;

                case "checkSign":
                    in = new Scanner(System.in);
                    System.out.print("Input a name file, for which you want to create sign: ");
                    filename = in.nextLine();
                    System.out.print("Input a name file with open key: ");
                    String openKeyfile = in.nextLine();
                    checkSign(filename, openKeyfile);
                    break;
                case "quit":
                    condition = false;
                    break;

                default:
                    break;
            }
            
        }
        
        
    }
}
