#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <sys/types.h>
#include "des.h"
#include<time.h>   //用到clock()函数

#define DEBUG23
// #define ROTATE_LEFT(x, s, n) ((x) << (n)) | ((x) >> ((s) - (n)))
int main(){
    int begintime,endtime;
    begintime=clock();	//计时开始
    for(int i = 0; i < 1000 * 100 * 1; i++){
        // key[i%16] = i;
        test();
    }
    endtime = clock();	//计时结束
	printf("\n\nRunning Time：%dms\n", endtime-begintime);
    return 0;
    // desKey key = {0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31};
    desKey key = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    // desKey key = {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
    subKey skey;
#ifdef DEBUG
    printf("原始数据:\n");
    for(int i = 0; i < 8 ; i++){
        
        displayBits(key.key[i]);
        printf("%x\n", key.key[i]);
    }
#endif
    // 生成子密钥
    printf("子密钥生成过程:\n");
    getSubKey(&key, &skey);
#ifdef DEBUG1
    for(int i = 0; i < 16; i++){
        putchar('\n');
        printf("subkey[%d]: ", i+1);
        for(int j = 0; j < 56; j++){
            if((j +1) % 8 == 0){
                printf("   ");
            }
            printf("%d", skey.key[i][j]);
        }
    }
#endif
    // desData data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    desData data = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    uint64_t t;
    uint8_t tempData[64] = {0};
    reverseUint8(data.data, 8);
    memcpy(&t, data.data, 8);
    uint64_tToBit(t, tempData);     // 将8字节数据转换成64位

    
    // printf("\n t = %llx \n", t);
    desData out;
    printf("加密过程:\n");
    uint8_t* result = des(tempData, &skey);
#ifdef DEBUG1
    putchar('\n');
    for(int i= 0;i<64;i++){
        if(i%8 == 0){
            printf(" ");
        }
        printf("%d", result[i]);
    }
#endif
    putchar('\n');
    // desData resultData;
    // uint64_t resutl_64 = bitToUint64(result);
    // memcpy(&resultData.data, &resutl_64, 8);
    // reverseUint8(resultData.data, 8);
    reverseKey(&skey);
    printf("解密过程:\n");
    des(result,&skey);
}
void reverseKey(subKey *skey){
    uint8_t temp[56] = {0};
    for(int i =0; i < 8; i++){
        memcpy(temp, skey->key[i], 56);
        memcpy(skey->key[i], skey->key[15 - i], 56);
        memcpy(skey->key[15 - i], temp, 56);
    }
}
void IP(uint8_t *data){
    uint8_t temp[64];
    for(int i = 0; i < 64; i++){
        temp[i] = data[DesInitial[i] - 1];
    }
    memcpy(data, temp, 64);
}
void reverseUint8(uint8_t *data, uint8_t len){
    uint8_t tmp;
    for(int i = 0; i < len / 2; i++){
        tmp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = tmp;
    }
}
int uint32_tToBit(uint32_t num, uint8_t *bit){ // 32bit to bits OK
    for(int i = 0; i < 32; i++){
        bit[31 - i] = num & 0x01;
        num >>= 1;
    }
    return 0;
}
int uint64_tToBit(uint64_t num, uint8_t *bit){ // OK
    for(int i = 0; i < 64; i++){
        bit[63 - i] = num & 0x01;
        num >>= 1;
    }
    return 0;
}
int uint8_tToBit(uint8_t num, uint8_t *bit){
    for(int i = 0; i < 8; i++){
        bit[7 - i] = num & 0x01;
        num >>= 1;
    }
    return 0;
}
int uint4_tToBit(uint8_t num, uint8_t *bit){
    for(int i = 0; i < 4; i++){
        bit[3 - i] = num & 0x01;
        num >>= 1;
    }
    return 0;
}
desDataList *getDesDataList(char *path){        //获取需要加密的数据，并转换成64位列表
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
    {
        printf("open file error!");
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    int len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    desDataList *dataList = (desDataList *)malloc(sizeof(desDataList));
    desDataList *p = dataList->next;
    while (len > 0)
    {
        fread(p->data.data, 1, 8, fp);
        p->next = (desDataList *)malloc(sizeof(desDataList));
        p = p->next;
        len -= 8;
    }
    // 最后一项填充至64位
    if (len < 0)
    {
        int i;
        for (i = 0; i < 8 + len; i++)
        {
            p->data.data[i] = 0;
        }
    }
    p->next = NULL;
    fclose(fp);
    return dataList;
}
int writeDesResultList(char *path, desResultList *resultList){        //将加密结果写入文件
    FILE *fp = fopen(path, "wb");
    if (fp == NULL)
    {
        printf("open file error!");
        return 0;
    }
    desResultList *p = resultList->next;
    while (p != NULL)
    {
        fwrite(p->result.result, 1, 8, fp);
        p = p->next;
    }
    fclose(fp);
    return 1;
}
int PC_1(uint8_t *key, subKey *key2){        //PC-1置换 OK
    int i;
    for (i = 0; i < 56; i++)
    {
        key2->key[0][i] = key[DesTransform[i] - 1];
    }
    return 1;
}
int PC_2(subKey *key, uint8_t *ci_di, int num){ //PC-2置换 OK
    int i;
    uint8_t temp[48] = {0};
    for (i = 0; i < 48; i++)
    {
        temp[i] = ci_di[DesPermuted2[i] - 1];
        // printf("%d, ", DesPermuted2[i]);
    }
    memcpy(key->key[num], temp, 48);
#ifdef DEBUG
    printf("subkey[%d]: ", num + 1);
    for (i = 0; i < 48; i++)
    {
        if (i  % 8 == 0)
        {
            printf("   ");
        }
        printf("%d", key->key[num][i]);
    }
    printf("\n");
#endif
    return 0;
}
int getSubKey(desKey *key, subKey *key2){        //生成des子密钥 OK
    uint8_t temp[56], key_bits[64];
    // uint64_t fullKey = uint8_tToUint64(key->key);
    // uint64_tToBit(fullKey, key_bits);
    for(int i = 0; i < 8; i++){
        byteToBit(key->key[i], key_bits + i * 8);
#ifdef DEBUG1
        putchar('\n');
        printf("key_bits[%d]: ", i + 1);
        for(int j = 0; j < 8; j++){
            printf("%d", key_bits[i * 8 + j]);
        }
#endif
    }
    int cnt;
    // memset(key_bits, 0, 56);
    PC_1(key_bits, key2);
#ifdef DEBUG
    printf("\n after PC1 \n");
    for(int i = 0; i < 56; i++){
        if(i % 8 == 0){
            printf("   ");
        }
        printf("%d", key2->key[0][i]);
    }
    putchar('\n');
#endif
    uint8_t temp2[32] = {0};
    memcpy(temp, key2->key[0], 56);
    for(cnt = 0; cnt < 16; cnt++){//16轮跌代，产生16个子密钥
        memcpy(temp2, temp, 28);
        uint32_t t = bitToUint32(temp2);
        t = ROTATE_LEFT(t,DesRotations[cnt],28); //C[cnt] 
        t = t&0xfffffff0;
        uint32_tToBit(t, temp2);
        memcpy(temp, temp2, 28); //用于下一轮的C[cnt]

        memcpy(temp2, &temp[28], 28);
#ifdef DEBUG
        printf("\n D[%d]: ", cnt);
        for(int i = 0; i < 28; i++){
            printf("%d", temp2[i]);
        }
        putchar('\n');
#endif
        t = bitToUint32(temp2);
        t = ROTATE_LEFT(t,DesRotations[cnt],28); //D[cnt]
        t = t&0xfffffff0;
        uint32_tToBit(t, temp2);
        memcpy(&temp[28], temp2, 28);//用于下一轮的D[cnt]
#ifdef DEBUG
        printf("\n after %d round \n", cnt + 1);
        for(int i = 0; i < 56; i++){
            if(i % 8 == 0){
                printf("   ");
            }
            printf("%d", temp[i]);
        }
        putchar('\n');
#endif
        PC_2(key2,temp,cnt);//PC2置换，产生子密钥  
    }  
    return 1;  
}
void IP_1(uint8_t *data){  //IP逆置换 OK
    int i;
    uint8_t temp[64] = {0};
    for (i = 0; i < 64; i++)
    {
        temp[i] = data[DesTransform_1[i] - 1];
    }
    memcpy(data, temp, 64);
}
uint8_t *des(uint8_t *data, subKey *sonKey){        //单个des加密
    // uint8_t tempData[64] = {0};
    // // uint64_t t = uint8_tToUint64(data->data);
    // uint64_t t;
    // reverseUint8(data->data, 8);
    // memcpy(&t, data->data, 8);
    // printf("\n t = %llx \n", t);
    // uint64_tToBit(t, tempData);     // 将8字节数据转换成64位
    IP(data);       // IP置换
    uint8_t L[32] = {0};uint8_t R[32] = {0};
    memcpy(L, data, 32);
    memcpy(R, &data[32], 32);
    uint8_t L_t[32] = {0};uint8_t R_t[32] = {0};
    // uint8_t expansion[48] = {0};
    for (int i = 0; i < 16; i++)
    {   
        // printf("\n after %d round \n", i + 1);
        memcpy(L_t, R, 32); // L[i] = R[i-1]
        f_function(R, sonKey->key[i]); // f(R[i-1], K[i])
        XOR(R, L, 32); // R[i] = L[i-1] ^ f(R[i-1], K[i])
        memcpy(L, L_t, 32); // L[i] = R[i-1]
#ifdef DEBUG
        // printf("\n after %d round \n", i + 1);
        printf("L[%d]: ", i + 1);
        for(int i = 0;i < 32; i++){
            if(i % 8 == 0){
                printf("   ");
            }
            printf("%d", L[i]);
        }
        printf("\nR[%d]: ", i + 1);
        for(int i = 0;i < 32; i++){
            if(i % 8 == 0){
                printf("   ");
            }
            printf("%d", R[i]);
        }
        putchar('\n');
#endif
    }
    memcpy(data, R, 32);
    memcpy(&data[32], L, 32);
    IP_1(data);
#ifdef  DEBUG
    // putchar('\n');
    printf("\n 加解密后数据: \n");
    for(int i = 0; i < 64; i++){
        if(i % 8 == 0){
            printf("   ");
        }
        printf("%d", data[i]);
    }
#endif
    uint8_t *result = (uint8_t *)malloc(64);
    memcpy(result, data, 64);
    return result;
    
}
// desResultList *getDesResultList(desDataList data, desKey key){        //获取加密结果
//     desResultList *resultList = (desResultList *)malloc(sizeof(desResultList));
//     desResultList *p = resultList;
//     desDataList *q = &data;
//     subKey *sonKey = (subKey *)malloc(sizeof(subKey));
//     getSubKey(&key, sonKey);
//     while(q!=NULL){
//         p->next = (desResultList *)malloc(sizeof(desResultList));
//         p = p->next;
//         p->result = *des(&q->data, sonKey);
//         q = q->next;
//     }
//     p->next = NULL;
//     return resultList;
// }
int byteToBit(uint8_t byte, uint8_t *bit){ //字节转换成二进制 OK
    for (int i = 0; i < 8; i++)
    {
        bit[i] = (byte >> (7 - i)) & 1;
    }
#ifdef DEBUG1
    printf("    byteToBit: ");
    for (int i = 0; i < 8; i++)
    {
        printf("%d", bit[i]);
    }
#endif
    return 1;
}      
int bitToByte(uint8_t bit[8], uint8_t *byte){ //二进制转换成字节
    *byte = 0;
    for (int i = 0; i < 8; i++)
    {
        *byte |= bit[i] << (7 - i);
    }
    return 1;
}  
uint32_t bitToUint32(uint8_t bit[32]){ //二进制转换成32位无符号整数
    uint32_t result = 0;
    for (int i = 0; i < 32; i++)
    {
        result |= bit[i] << (31 - i);
    }
    return result;
}
int uint32ToBit(uint32_t num, uint8_t bit[32]){ //32位无符号整数转换成二进制
    for (int i = 0; i < 32; i++)
    {
        bit[i] = (num >> (31 - i)) & 1;
    }
    return 1;
}
int uint64ToBit(uint64_t num, uint8_t bit[64]){ //64位无符号整数转换成二进制
    for (int i = 0; i < 64; i++)
    {
        bit[i] = (num >> (63 - i)) & 1;
    }
    return 1;
}
uint64_t bitToUint64(uint8_t bit[64]){ //二进制转换成64位无符号整数
    uint64_t result = 0;
    for (int i = 0; i < 64; i++)
    {
        result |= bit[i] << (63 - i);
    }
    return result;
}
uint64_t uint8_tToUint64(uint8_t *byte){ //字节数组转换成64位无符号整数
    uint64_t result = 0;
    for (int i = 0; i < 8; i++)
    {
        uint8_t temp = byte[i];
        result |= temp << (56 - i * 8);
#ifdef DEBUG
        printf("byte[%d]: %x\t", i, byte[i]);
        printf("result: %lx\n", result);
#endif
    }
    return result;
}
int ex32To48(uint8_t bit[32], uint8_t bit2[48]){ //32位扩展成48位 OK
    for (int i = 0; i < 48; i++)
    {
        bit2[i] = bit[DesExpansion[i] - 1];
    }
    return 1;
}
int f_function(uint8_t R[32], uint8_t key[48]){
    uint8_t expansion[48] = {0};
    ex32To48(R, expansion);
#ifdef DEBUG
    printf("expansion: ");
    for (int i = 0; i < 48; i++)

    {   
        if(i%8==0) printf(" ");
        printf("%d", expansion[i]);
    }
    printf("\n");
#endif
    XOR(expansion, key, 48);
#ifdef DEBUG
    printf("expansion XOR: ");
    for (int i = 0; i < 48; i++)

    {   
        if(i%8==0) printf(" ");
        printf("%d", expansion[i]);
    }
    printf("\n");
#endif
#ifdef DEBUG
    printf("key: ");
    for (int i = 0; i < 48; i++)

    {   
        if(i%8==0) printf(" ");
        printf("%d", key[i]);
    }
    printf("\n");
#endif
    S_box(expansion, R);
#ifdef DEBUG
    printf("S_BOX: ");
    for (int i = 0; i < 32; i++)
    {
        if((i)%8==0) printf(" ");
        printf("%d", R[i]);
    }
    printf("\n");
#endif
    P_box(R);
#ifdef DEBUG
    printf("P: ");
    for (int i = 0; i < 32; i++)
    {
        if(i%8==0) printf(" ");
        printf("%d", R[i]);
    }
    printf("\n");
#endif
    return 1;
}
int XOR(uint8_t *a, uint8_t *b, int len){ //异或 OK
    for (int i = 0; i < len; i++)
    {
        a[i] ^= b[i];
    }
    return 1;
}
int S_box(uint8_t *bit48, uint8_t *bit32){ //S盒
    uint8_t temp[8] = {0};
    for (int i = 0; i < 8; i++)
    {
        memcpy(temp, &bit48[i * 6], 6);
        uint8_t row = (temp[0] << 1) + temp[5];
        uint8_t col = (temp[1] << 3) + (temp[2] << 2) + (temp[3] << 1) + temp[4];
        uint8_t a = DesSbox[i][row][col];
        uint4_tToBit(DesSbox[i][row][col], &bit32[i * 4]);
    }
    return 1;
}
int P_box(uint8_t *bit32){ //P盒
    uint8_t temp[32] = {0};
    memcpy(temp, bit32, 32);
    for (int i = 0; i < 32; i++)
    {
        bit32[i] = temp[DesPbox[i] - 1];
    }
    return 1;
}
void displayBits(uint8_t data){
    int i;
    for(i = 0; i < 8; i++){
        printf("%d", (data >> (7 - i)) & 1);
    }
    printf("\t");
}

void test(){
    // desKey key = {0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31};
    desKey key = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    // desKey key = {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1};
    subKey skey;
#ifdef DEBUG
    printf("原始数据:\n");
    for(int i = 0; i < 8 ; i++){
        
        displayBits(key.key[i]);
        printf("%x\n", key.key[i]);
    }
#endif
    // 生成子密钥
    // printf("子密钥生成过程:\n");
    getSubKey(&key, &skey);
#ifdef DEBUG1
    for(int i = 0; i < 16; i++){
        putchar('\n');
        printf("subkey[%d]: ", i+1);
        for(int j = 0; j < 56; j++){
            if((j +1) % 8 == 0){
                printf("   ");
            }
            printf("%d", skey.key[i][j]);
        }
    }
#endif
    // desData data = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    desData data = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
    uint64_t t;
    uint8_t tempData[64] = {0};
    reverseUint8(data.data, 8);
    memcpy(&t, data.data, 8);
    uint64_tToBit(t, tempData);     // 将8字节数据转换成64位

    
    // printf("\n t = %llx \n", t);
    desData out;
    // printf("加密过程:\n");
    uint8_t* result = des(tempData, &skey);
#ifdef DEBUG1
    putchar('\n');
    for(int i= 0;i<64;i++){
        if(i%8 == 0){
            printf(" ");
        }
        printf("%d", result[i]);
    }
#endif
    // putchar('\n');
    // desData resultData;
    // uint64_t resutl_64 = bitToUint64(result);
    // memcpy(&resultData.data, &resutl_64, 8);
    // reverseUint8(resultData.data, 8);
    reverseKey(&skey);
    // printf("解密过程:\n");
    des(result,&skey);
}