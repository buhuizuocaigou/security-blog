#include<stdio.h>
int SumOfElements(int a[]){//这里记得用int  提示void 不能初始化int类型的实体
int i=0;
int sum =0;
int size=sizeof(a)/sizeof(a[0]);  //利用sizeof  自动识别数组内元素 的个数 并传输出去
for (i=0; i<size; i++){//将他们数组内的元素相加 求和最后输出出去
sum +=a[i];
}
printf("zheshi sum of %d\n",sum);
return sum;

}
int main(){
    int a[]={1,2,3,4,5,8,9};
    int total=SumOfElements(a);//我定义一个total 代指数组内的和 并且调用一个函数 这个函数的功能是计算数组中各种元素的和
    printf("this is a sum of elements%d\n",total);
    return 0;
}