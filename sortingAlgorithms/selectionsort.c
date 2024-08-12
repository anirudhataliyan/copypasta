#include <stdio.h>
void selectionsort(int arr[], int length);
void swap(int *a, int *b);
int main() {
    int a[] = {5, 9, 7, 6, 4, 0, 2, 3, 8, 1};
    int length = 10;
    selectionsort(a, length); 
    for (int i = 0; i < length; i++){
        printf("%d ", a[i]);
    }
    return 0;
}
void swap(int *a,int *b){
    int temp = *a;
    *a = *b; 
    *b = temp; 
}
void selectionsort(int a[], int length){
    for(int i=0; i<length-1; i++){
        int min_pos = i;
        for(int j = i+1; j<length; j++){
            if (a[j] < a[min_pos]){
                min_pos = j;
            }
        }
        if(min_pos != i){
            swap(&a[i], &a[min_pos]); 
        }
    }
}
