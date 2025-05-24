// Function call test
int add(int x, int y) {
    return x + y;
}

int multiply(int x, int y) {
    int result = 0;
    for (int i = 0; i < y; i++) {
        result = add(result, x);
    }
    return result;
}

int main() {
    int a = 4;
    int b = 7;
    int sum = add(a, b);
    int product = multiply(a, b);
    return sum + product;
}