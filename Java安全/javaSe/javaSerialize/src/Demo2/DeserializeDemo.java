package Demo2;
import java.io.*;
import Demo1.Employee;

public class DeserializeDemo {
    public static void main(String [] args){
        Employee e = null;
        try{
            FileInputStream fileIn = new FileInputStream("./test.ser");
            ObjectInputStream in = new ObjectInputStream(fileIn);
            e = (Employee) in.readObject();
            in.close();

        }catch (IOException i ){
            i.printStackTrace();
            return;
        }catch (ClassNotFoundException c){
            System.out.println("Employee class not found");

        }
        System.out.println("Deserialized Employee..");
        System.out.println("Name:" + e.name);
        System.out.println("Address: "+ e.address);
        System.out.println("SSN: " + e.SSN);



    }

}
