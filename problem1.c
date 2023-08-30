// Bruteforce attempt
#include<stdio.h> 

int bruteforce_method(int arr[], int n, int target){
    for (int i = 0; i < n - 1; i++) {
        for (int j = i; j < n ; j++) {
            if (arr[i]==arr[j]){
                continue;
            }else {
                if (arr[i] + arr[j] == target) {
                    printf("[%d, %d]\n", arr[i], arr[j]);
                
            }
        }
    }
}}
int main(){
    int array[5];
    int target;
    for(int i=0; i<5; i++){
        printf("Enter %d number: ", i+1);
        scanf("%d", &array[i]);
    }
    printf("Enter the target: ");
    scanf("%d", &target);
    bruteforce_method(array, 5, target); 
    return 0; 
}
