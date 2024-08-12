#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Stack {
    int top;
    unsigned capacity;
    char* array;
} Stack;

Stack* createStack(unsigned capacity) {
    Stack* stack = (Stack*)malloc(sizeof(Stack));
    stack->capacity = capacity;
    stack->top = -1;
    stack->array = (char*)malloc(stack->capacity * sizeof(char));
    return stack;
}

int isEmpty(Stack* stack) { return stack->top == -1; }

void push(Stack* stack, char item) {
    stack->array[++stack->top] = item;
}
char pop(Stack* stack) {
    if (isEmpty(stack))
        return '\0';
    return stack->array[stack->top--];
}
int areParenthesesBalanced(char* expr) {
    Stack* stack = createStack(strlen(expr));
    if (!stack) return 0;
    for (int i = 0; expr[i]; i++) {
        if (expr[i] == '(') {
            push(stack, '(');
        } else if (expr[i] == ')') {
            if (isEmpty(stack)) {
                return 0;
            } else {
                pop(stack);
            }
        }
    }
    int isBalanced = isEmpty(stack);
    free(stack->array);
    free(stack);
    return isBalanced;
}
int main() {
    char expr[100];
    printf("Enter an expression to check for balanced parentheses: ");
    fgets(expr, sizeof(expr), stdin);
    expr[strcspn(expr, "\n")] = 0;

    if (areParenthesesBalanced(expr)) {
        printf("Parentheses are balanced\n");
    } else {
        printf("Parentheses are not balanced\n");
    }
    return 0;
}
