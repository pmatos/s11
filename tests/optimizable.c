// Code with obvious optimization opportunities
int main() {
    int x = 10;
    
    // This should be optimizable: x = x + 1 -> x += 1 or similar
    x = x + 1;
    
    // Dead code that might be optimized away
    int unused = 42;
    
    // Redundant operations
    int y = x;
    y = y + 0;  // Adding zero
    y = y * 1;  // Multiplying by one
    
    // Constant folding opportunity
    int z = 2 + 3 * 4;
    
    return x + y + z;
}