#include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <malloc.h>
#include <stdint.h>
// #include <sys/types.h>
#include "sm4.h"

#include<time.h>   //用到clock()函数

#define DEBUG2

char buffer[16];

uint8_t key[16] = {0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76};

uint32_t rk[32];
uint32_t X[36];

int main(){
    int begintime,endtime;
    begintime=clock();	//计时开始
    for(int i = 0; i < 1000 * 100 * 1; i++){
        // key[i%16] = i;
        test();
    }
    endtime = clock();	//计时结束
	printf("\n\nRunning Time：%dms\n", endtime-begintime);
    
    // uint8_t key[16] = {0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76};
    char data[17] = {0};
    uint8_t out[17] = {0};

    char filename[] = "test.txt";
    char outfilename[] = "out.txt";
    FILE *fp = fopen(filename, "rb");
    FILE *outfp = fopen(outfilename, "wb");
    if(fp == NULL || outfp == NULL){
        printf("open file error");
        return -1;
    }
    int len = 0;
    while((len = fread(data, 1, 16, fp)) > 0){
        if(len < 16){
            while(len < 16){
                data[len] = 0;
                len++;
            }
            // memset(data + len, 0, 16 - len);
        }
        encrypt((uint8_t *)data, (uint8_t *)out, ENCRYPT);
        // printf("out: %s, data: %s",out,data);
        encrypt((uint8_t *)out, (uint8_t *)out, DECRYPT);
        // printf("out: %s, data: %s",out,data);
        fprintf(outfp, "%s", out);
    }
}

int externKey(uint32_t *key, uint32_t *rk) //扩展密钥 OK
{
    int i = 0;
    uint32_t k[36] = {0};
    uint32_t tmp1, tmp2;
    for (i = 0; i < 4; i++)     // (K0, K1, K2, K3) = (MK0 ^ SM4FK[0], MK1 ^ SM4FK[1], MK2 ^ SM4FK[2], MK3 ^ SM4FK[3])
    {
        k[i] = key[i] ^ SM4_FK[i];
    }

    for (i = 0; i < 32; i++)    // rk[i] = k[i+4] = k[i] ^ T(k[i+1] ^ k[i+2] ^ k[i+3] ^ SM4CK[i])
    {   
        tmp1 = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ SM4_CK[i];
        tTransform(&tmp1, &tmp2, KEY);
        rk[i] = k[i] ^ tmp2;
        k[i + 4] = rk[i];
    }
    return 0;
}

int sm4(uint8_t *in, uint32_t *out, uint32_t *rk, int mode) //加解密
{
    uint32_t X[36] = {0};
    for(int i = 0; i < 4; i++){
        X[i] = *(uint32_t *)(in + i * 4);   // 前四位为明文
    }
    for(int i = 0; i < 32; i++){
        if(mode == ENCRYPT){        // 加密
            rTransform(X + i, X + i + 4, &rk[i], DATA);
#ifdef DEBUG
            printf("rk[%d] = ", i);
            dispWord(&rk[i], 1, 0);
            printf("\tX[%d] = ", i);
            dispWord(&X[i + 4], 1, 1);
#endif
        }
        else{
            rTransform(X + i, X + i + 4, &rk[31 - i], DATA);
        }
    }
    reverse(X + 32, out);
    return 0;
}

int sBox(uint8_t *in, uint8_t *out) //S盒 OK
{
    out[0] = SM4_SBOX[in[0]];
    return 0;
}

int lTransform(uint32_t *in, uint32_t *out, int mode) //L线性变换 OK
{
    uint32_t C;
    if(mode == DATA){     // 加解密
        C = *in ^ (ROTATE_LEFT(*in, 2, 32)) ^ (ROTATE_LEFT(*in, 10, 32)) ^ (ROTATE_LEFT(*in, 18, 32)) ^ (ROTATE_LEFT(*in, 24, 32)); // C=L(B) = B ^ rotl(B, 2) ^ rotl(B, 10) ^ rotl(B, 18) ^ rotl(B, 24)
        *out = C;
    }
    else{ // 密钥拓展
        C = *in ^ (ROTATE_LEFT(*in, 13, 32)) ^ (ROTATE_LEFT(*in, 23, 32)); // C=L(B) = B ^ rotl(B, 13) ^ rotl(B, 23)
        *out = C;
    }
    return 0;
}

int tTransform(uint32_t *in, uint32_t *out, int mode) //合成变化 OK
{
    uint32_t X;
    uint8_t tmp[4] = {0};
    uint8_t *in_8  = (uint8_t *)in;
    for(int i = 0; i < 4; i++){
        sBox(in_8 + i, &tmp[i]);  // S盒
    }
    lTransform((uint32_t *)tmp, &X, mode); // L线性变换
    *out = X;
    return 0;
}

int rTransform(uint32_t *in, uint32_t *out, uint32_t *rk, int mode) //轮变换 
{
    uint32_t X;
    uint32_t B;
    B = in[1] ^ in[2] ^ in[3] ^ *rk; // B = (X1 ^ X2 ^ X3 ^ rk)
    tTransform(&B, &X, mode); // T(B)
    X = in[0] ^ X; // X = X0 ^ T(B)
    out[0] = X;
    return 0;
}

int reverse(uint32_t *in, uint32_t *out) //反序处理
{
    for(int i = 0; i < 4; i++){
        out[i] = in[3 - i];
    }
    return 0;
}

void dispWord(uint32_t *in, int len, int next) //打印
{
    for(int i = 0; i < len; i++){
        printf("%08X ", in[i]);
    }
    if(next == 1)
        printf("\n");
}

void test()
{
    // uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t key[16] = {0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76};
    // uint8_t data[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t data[16] = {0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76};
    uint8_t out[16] = {0};
    uint32_t rk[32];
    uint32_t X[36];
#ifdef DEBUG
    printf("key     = ");
    dispWord((uint32_t *)key, 4, 1);
#endif

#ifdef DEBUG
    printf("plain   = ");
    dispWord((uint32_t *)data, 4, 1);
#endif

    externKey((uint32_t *)key, rk);
#ifdef DEBUG1
    for(int i = 0; i < 32; i++){
        printf("rk[%d] = ", i);
        dispWord(&rk[i], 1, 1);
    }
#endif
    sm4(data, (uint32_t *)out, rk, ENCRYPT);
// #ifdef DEBUG
//     for(int i = 0; i < 32; i++){
//         printf("X[%d] = ", i);
//         dispWord(&X[i], 1);
//     }
// #endif
#ifdef DEBUG
    printf("encrypt = ");
    dispWord((uint32_t *)out, 4, 1);
#endif
    sm4(out, (uint32_t *)out, rk, DECRYPT);
#ifdef DEBUG
    printf("plain   = ");
    dispWord((uint32_t *)out, 4, 1);
#endif
}

void encrypt(uint8_t *data, uint8_t *out, int mode)
{
    externKey((uint32_t *)key, rk);
    sm4(data, (uint32_t *)out, rk, mode);
}

