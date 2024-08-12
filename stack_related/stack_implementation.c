#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct stack {
  unsigned int size;
  int top;
  int *arr;
} stack;

bool is_Empty(stack *s) { 
    if (s->top < 0) {
        return true;
    } else {
        return false;
    }
}

bool is_Full(stack *s) { 
    if (s->top == s->size - 1) {
       return true;
    } else {
      return false;
    }
}

// "i" will start from '0'.
int peek(stack *s, int i) { 
    if (s->top - i < 0) {
        return -1;
    } else {
        return s->arr[s->top - i];
    }
}

int push(stack *s, int value) {
  if (is_Full(s))
    return printf("Stack Overflow. %d Cannot be pushed.\n", value);
  s->top++;
  s->arr[s->top] = value;
  return printf("Pushed %d.\n", value);
}

int pop(stack *s) {
  if (is_Empty(s))
    return printf("Stack Underflow. Cannot pop.\n");
  int temp = s->arr[s->top];
  s->top--;
  printf("Poped value %d.\n", temp);
  return 1;
}

int main(void) {
  stack *s = (stack *)malloc(sizeof(stack));
  s->size = 10;
  s->top = -1;
  s->arr = (int *)malloc(s->size * sizeof(int));

  push(s, 2);
  push(s, 20);
  push(s, 21);
  push(s, 27);
  push(s, 3);
  push(s, 7);

  printf("\n");
  printf("AT POSITION TWO ELEMENT IS %d\n", peek(s, 2)); 
  free(s->arr);
  free(s);
  return 0;
}

