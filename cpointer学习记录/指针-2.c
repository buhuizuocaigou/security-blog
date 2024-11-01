#include<stdio.h>//利用*p指针来将 函数的局部变量传递到内部
void chuandi( int *p){
   *p =*p +1;//我告诉main ，不要在临时在strack里面开辟的一块儿区域做变化，要根据这个我给你的地址 找对应的人去做变化，这样才能追究责任到闹事的人身上，我就是个传话的 ，我身上有闹事的人的地址我告诉你
}
int main(){
    int a;
    a =1024;
    chuandi(&a);//测试chuandi这个函数内对a做的变量加减等 是否带出来了
    printf("a value is %d\n",a);
    return 0;
}