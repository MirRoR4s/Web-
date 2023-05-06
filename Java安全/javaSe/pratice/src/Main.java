public class Main {
    //实例变量：从属于对象;
    double pow = Math.pow(2,3);



    //修饰符，不存在先后顺序
    static final double PI = 3.14;
    int age;
    static double salary = 2500;


    public static void main(String[] args) {
        //局部变量：必须声明和初始化值
        int i = 10;
        System.out.println(i);
        Main a = new Main();
        System.out.println(a.age);
        System.out.println(Main.salary);



    }
    public void add(){

    }
}