#include <iostream>

int main()
{
    size_t N = 1024 * 1024;
    char A[N];
    char B[N];
    char C[N];

    while (true)
    {
        for (size_t i = 0; i < N; i++) {
            A[i] = 1;
            B[i] = 2;
        }

        for (size_t i = 0; i < N; i++) {
            C[i] = A[i] + B[i];
        }
    }
    
    return 0;
}