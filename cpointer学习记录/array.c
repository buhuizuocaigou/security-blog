#include<stdio.h>
int main(){
int a[]={2,12,4,54,1,5,4};
int i;
for (i=0;i<6;i++){
    printf("this is address%d\n",&a[i]);
    printf("this is address %d\n",a+i);
    printf("this is value %d\n",a[i]);
    printf("this is value %d\n",*(a+i));
}
return 0;
}
 