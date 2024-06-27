#include <stdio.h>
#include <stdlib.h>

#define MAX 100 // Define the maximum size of the stack

// Define a structure to represent the stack
typedef struct {
    int data[MAX];
    int top;
} Stack;

// Function to initialize the stack
void initialize(Stack* stack) {
    stack->top = -1;
}

// Function to check if the stack is empty
int isEmpty(Stack* stack) {
    return stack->top == -1;
}

// Function to check if the stack is full
int isFull(Stack* stack) {
    return stack->top == MAX - 1;
}

// Function to push an element onto the stack
void push(Stack* stack, int value) {
    if (isFull(stack)) {
        printf("Stack is full. Cannot push %d\n", value);
        return;
    }
    stack->data[++(stack->top)] = value;
}

// Function to pop an element from the stack
int pop(Stack* stack) {
    if (isEmpty(stack)) {
        printf("Stack is empty. Cannot pop an element.\n");
        return -1; // Return an error value
    }
    return stack->data[(stack->top)--];
}

// Function to get the top element of the stack
int top(Stack* stack) {
    if (isEmpty(stack)) {
        printf("Stack is empty. No top element.\n");
        return -1; // Return an error value
    }
    return stack->data[stack->top];
}

// Function to get the size of the stack
int size(Stack* stack) {
    return stack->top + 1;
}

int main() {
    Stack stack;
    initialize(&stack);
    return 0;
}
