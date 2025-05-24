// Array operations test
int main() {
    int arr[5] = {1, 2, 3, 4, 5};
    int sum = 0;
    
    // Array access and accumulation
    for (int i = 0; i < 5; i++) {
        sum += arr[i];
    }
    
    // Array modification
    arr[0] = arr[1] + arr[2];
    
    return sum + arr[0];
}