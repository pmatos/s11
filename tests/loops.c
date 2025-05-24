// Loop and conditional test
int main() {
    int sum = 0;
    for (int i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            sum += i;
        }
    }
    return sum;
}