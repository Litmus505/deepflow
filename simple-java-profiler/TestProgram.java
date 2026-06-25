import java.util.Random;

public class TestProgram {
    private static final Random random = new Random();

    public static void main(String[] args) throws InterruptedException {
        System.out.println("Java Profiling Test Program Started...");
        
        while (true) {
            methodA();
            Thread.sleep(100);
        }
    }

    private static void methodA() {
        methodB();
        methodC();
    }

    private static void methodB() {
        long sum = 0;
        for (int i = 0; i < 10000; i++) {
            sum += random.nextLong();
        }
        System.out.println("Method B completed, sum: " + sum);
    }

    private static void methodC() {
        int[] array = new int[1000];
        for (int i = 0; i < array.length; i++) {
            array[i] = random.nextInt(1000);
        }
        sortArray(array);
    }

    private static void sortArray(int[] array) {
        for (int i = 0; i < array.length - 1; i++) {
            for (int j = 0; j < array.length - i - 1; j++) {
                if (array[j] > array[j + 1]) {
                    int temp = array[j];
                    array[j] = array[j + 1];
                    array[j + 1] = temp;
                }
            }
        }
    }
}
