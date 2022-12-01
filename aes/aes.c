#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdint.h>
#include <sys/types.h>
#include "aes.h"
#include<time.h>   //用到clock()函数

#define DEBUG 0

uint8_t plain_text_matrix[4][4] = {0};
uint8_t temp_key_matrix[4][4] = {0};

int main(){
    generateMulTab();
    // uint8_t plain_text[16] = {0x00, 0x01, 0x00, 0x01, 0x01, 0xa1, 0x98, 0xaf, 0xda, 0x78, 0x17, 0x34, 0x86, 0x15, 0x35, 0x66};
    // uint8_t key[16] = {0x00, 0x01, 0x20, 0x01, 0x71, 0x01, 0x98, 0xae, 0xda, 0x79, 0x17, 0x14, 0x60, 0x15, 0x35, 0x94};
    uint8_t plain_text[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};

    uint8_t subkey[11][16] = {0};
    uint8_t cipher_text[16] = {0};
    // 密钥扩展
    KeyExpansion(key, subkey);
#ifdef DEBUG
    printf("subkey:\n");
    for(int i = 0;i<11;i++){
        printf("key %d:",i);
        for(int j = 0;j<16;j++){
            printf("%02x ", subkey[i][j]);
        }
        printf("\n");
    }
#endif
    // 加解密
    AES_Encrypt(plain_text, subkey, cipher_text);
    AES_Decrypt(cipher_text, subkey, plain_text);
}
// 拓展密钥 uint8 key[16] uint8 subkey[11][16]
void KeyExpansion(uint8_t *key, uint8_t subkey[11][16]){ // OK
    uint8_t temp[4][4] = {0};
    uint8_t temp2[4][4] = {0};
    // 把 key 复制到 subkey[0]
    for(int i = 0; i < 16; i++){
        subkey[0][i] = key[i];
    }
    // 生成 subkey[1] ~ subkey[10]
    for(int i = 1; i < 11; i++){
        Array2Matrix(subkey[i-1], temp);
        getOneSubKey(temp, temp2, i - 1);
        Matrix2Array(temp2, subkey[i]);
    }
}
// 获取一个子密钥 uint8 key0[4][4], uint8 key1[4][4]
void getOneSubKey(uint8_t key0[4][4], uint8_t key1[4][4], uint8_t round){ // OK
    // 处理第三列
    uint8_t temp[4] = {0};
    // key[][3]左环移位 后S盒变换
    for(int i = 0; i < 4; i++){
        temp[i] = key0[(i+1)%4][3];
    }
    for(int i = 0; i < 4; i++){
        temp[i] = S_BOX[temp[i]];
    }
    // 与{RC[round], 0, 0, 0}异或
    temp[0] = temp[0] ^ RC[round];
    // 与第一列异或
    for(int i = 0; i < 4; i++){
        key1[i][0] = key0[i][0] ^ temp[i];
    }
    // 与第二 - 四列异或
    for(int i = 0; i < 4; i++){
        for(int j = 1; j < 4; j++){
            key1[i][j] = key0[i][j] ^ key1[i][j-1];
        }
    }
}

// addRoundKey 运算
void AddRoundKey(uint8_t state[4][4], uint8_t w[4][4]){
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = state[i][j] ^ w[i][j];
        }
    }
}
// MixColumn 运算 
void MixColumn(uint8_t state[4][4]){
    Transpose(state); // 转置，方便计算
    uint8_t temp[4][4] = {0};
    for(int i = 0; i < 4; i++){
        for(int j = 0;j<4;j++){
            temp[i][j] = GfPolyMul(mixColumnMatrix[i], state[j], 4);
        }
    }
    // transpose(temp);
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[i][j] = temp[i][j];
        }
    }
}
// inverse MixColumn 运算 FIXME
void inverseMixColumn(uint8_t state[4][4]){
    Transpose(state); // 转置，方便计算
    uint8_t temp[4][4] = {0};
    for(int i = 0; i < 4; i++){
        for(int j = 0;j<4;j++){
            temp[i][j] = GfPolyMul(inverseMixColumnMatrix[i], state[j], 4);
        }
    }
    // transpose(temp);
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[i][j] = temp[i][j];
        }
    }
}
// ShiftRow 运算 1-3行变化 FIXME 可以考虑转换为int再做移位加快运算速度
void ShiftRow(uint8_t state[4][4]){
    int i, j;
    uint8_t temp[4][4] = {0};
    for(i = 1; i < 4; i++){
        for(j = 0; j < 4; j++){
            temp[i][j] = state[i][(j + i)%4];
        }
    }
    for(i = 1; i < 4; i++){
        for(j = 0; j < 4; j++){
            state[i][j] = temp[i][j];
        }
    }
}
// inverse ShiftRow 运算 FIXME 可以考虑转换为int再做移位加快运算速度
void inverseShiftRow(uint8_t state[4][4]){
    int i, j;
    uint8_t temp[4][4] = {0};
    for(i = 1; i < 4; i++){
        for(j = 0; j < 4; j++){
            temp[i][j] = state[i][(j - i + 4)%4];
        }
    }
    for(i = 1; i < 4; i++){
        for(j = 0; j < 4; j++){
            state[i][j] = temp[i][j];
        }
    }
}
// SubBytes 运算
void SubBytes(uint8_t state[4][4]){
    int i,j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = S_BOX[state[i][j]];
        }
    }
}
// inverse SubBytes 运算
void inverseSubBytes(uint8_t state[4][4]){
    int i,j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            state[i][j] = inverseS_BOX[state[i][j]];
        }
    }
}

void AES_Encrypt(uint8_t *plain_text ,uint8_t subkey[11][16], uint8_t *cipher_text){ //OK
    // 把明文转化为矩阵
    Array2Matrix(plain_text, plain_text_matrix);
    // 把密钥转化为矩阵
    Array2Matrix(subkey[0], temp_key_matrix);   
    // 轮密钥加一次
#ifdef DEBUG
    printf("明文\n");
    DisplayMatrix(plain_text_matrix);
    printf("密钥\n");
    DisplayMatrix(temp_key_matrix);
#endif
    AddRoundKey(plain_text_matrix, temp_key_matrix);
    for(int i = 1; i < 11; i++){
        // 把密钥转化为矩阵
        Array2Matrix(subkey[i], temp_key_matrix);
#ifdef DEBUG
        printf("第%d轮密钥加之后:\n", i);
        DisplayMatrix(plain_text_matrix);
#endif
        // 字节代换
        SubBytes(plain_text_matrix);
#ifdef DEBUG
        printf("字节代换之后:\n");
        DisplayMatrix(plain_text_matrix);
#endif
        // 行移位
        ShiftRow(plain_text_matrix);
#ifdef DEBUG
        printf("行移位之后:\n");
        DisplayMatrix(plain_text_matrix);
#endif
        if(i < 10){
            // 列混淆
            MixColumn(plain_text_matrix);
#ifdef DEBUG
            printf("列混淆之后:\n");
            DisplayMatrix(plain_text_matrix);
#endif
        }
        // 轮密钥加
        AddRoundKey(plain_text_matrix, temp_key_matrix);
    }
    Matrix2Array(plain_text_matrix, cipher_text);
#ifdef DEBUG
    printf("密文:\n");
    DisplayMatrix(plain_text_matrix);
#endif
}
void AES_Decrypt(uint8_t *cipher_text ,uint8_t subkey[11][16], uint8_t *plain_text){
    // 把密文转化为矩阵
    Array2Matrix(cipher_text, plain_text_matrix);
    // 把密钥转化为矩阵
    Array2Matrix(subkey[10], temp_key_matrix);
    // 轮密钥加一次
#ifdef DEBUG
    printf("密文\n");
    DisplayMatrix(plain_text_matrix);
    printf("密钥\n");
    DisplayMatrix(temp_key_matrix);
#endif
    AddRoundKey(plain_text_matrix, temp_key_matrix);
#ifdef DEBUG
    printf("第%d轮密钥加之后:\n", 11);
    DisplayMatrix(plain_text_matrix);
#endif
    for(int i = 9; i >= 0; i--){
        // 把密钥转化为矩阵
        Array2Matrix(subkey[i], temp_key_matrix);
        // 行移位
        inverseShiftRow(plain_text_matrix);
#ifdef DEBUG
        printf("行移位之后:\n");
        DisplayMatrix(plain_text_matrix);
#endif
        // 字节代换
        inverseSubBytes(plain_text_matrix);
#ifdef DEBUG
        printf("字节代换之后:\n");
        DisplayMatrix(plain_text_matrix);
#endif
        // 轮密钥加
        AddRoundKey(plain_text_matrix, temp_key_matrix);
#ifdef DEBUG
        printf("第%d轮密钥加之后:\n", i);
        DisplayMatrix(plain_text_matrix);
#endif
        if(i > 0){
            // 列混淆
            inverseMixColumn(plain_text_matrix);
#ifdef DEBUG
            printf("列混淆之后:\n");
            DisplayMatrix(plain_text_matrix);
#endif
        }
    }
#ifdef DEBUG
    printf("明文:\n");
    DisplayMatrix(plain_text_matrix);
#endif
    Matrix2Array(plain_text_matrix, cipher_text);
}
// 16 字节数组转换为 4*4 矩阵
uint8_t Array2Matrix(uint8_t *array, uint8_t matrix[4][4]){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            matrix[j][i] = array[i*4+j];
        }
    }
    return 0;
}
// 4*4 矩阵转换为 16 字节数组
uint8_t Matrix2Array(uint8_t matrix[4][4], uint8_t *array){
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            array[i*4+j] = matrix[j][i];
        }
    }
    return 0;
}

// GF(2^8)上的加法
uint8_t GfAdd(uint8_t a, uint8_t b)
{
    return a ^ b;
}
// GF(2^8)上的多项式加法
uint8_t GfPolyAdd(uint8_t *a, uint8_t *b, uint8_t *result, int len)
{
    // a, b,result是多项式,a[i]表示a的第i项系数, 长度为4
    int i;
    for (i = 0; i < len; i++)
    {
        result[i] = GfAdd(a[i], b[i]);
    }
    return 0;
}
// GF(2^8)上的乘法
uint8_t GfMul(uint8_t a, uint8_t b) // OK
{
    uint8_t temp[8] = { a };
	uint8_t tempmultiply = 0x00;
	int i = 0;
	for (i = 1; i < 8; i++) {
		temp[i] = Xtime(temp[i - 1]);
	}
	tempmultiply = (b & 0x01) * a;
	for (i = 1; i <= 7; i++) {
		tempmultiply ^= (((b >> i) & 0x01) * temp[i]);
	}
	return tempmultiply;
}
// GF(2^8)上的多项式乘法
uint8_t GfPolyMul(uint8_t *a, uint8_t *b, int len)
{
    uint8_t temp =  0 ;
    for(int i = 0; i < len; i++){
        temp ^= GfMul(a[i], b[i]);
        // temp ^= temp;
    }
    return temp;
}
void generateMulTab(){
    //选择生成元3作为构造乘法表的基础
    const int N = 3;
    unsigned char tmp = 1;
    for(int i = 1; i < 256; i ++){
        tmp = GfMul(tmp, N);
        exp_table[i] = tmp;
        log_table[tmp] = i;
    }
}
uint8_t GFfastMul(uint8_t a, uint8_t b){
    //利用exp和log来查表实现乘法
    if(a == 0 || b == 0)
        return 0;
    //a = 3 ^ m, b = 3 ^ n;   a * b = 3 ^ m * 3 ^ n = 3 ^ (m + n)
    int m = log_table[a], n = log_table[b];
    return exp_table[(m+n)>255?(m+n-255):(m+n)];
}
// 矩阵转置
void Transpose(uint8_t matrix[4][4]){
    for(int i = 0; i < 4; i++){
        for(int j = i + 1; j < 4; j++){
            // 位运算交换
            matrix[i][j] ^= matrix[j][i];
            matrix[j][i] ^= matrix[i][j];
            matrix[i][j] ^= matrix[j][i];
        }
    }
}
// XTIME
uint8_t Xtime(uint8_t x){
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}
void DisplayMatrix(uint8_t matrix[4][4]){
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            printf("%02x ", matrix[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}
void DisplayArray(uint8_t *array, int len){
    int i;
    for(i = 0; i < len; i++){
        printf("%02x ", array[i]);
    }
    printf("\n");
}