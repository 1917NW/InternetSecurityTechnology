
#include<cstring>
#include "des.h"

CDesOperate::CDesOperate() {
    for(int i = 0; i < 16; i++) {
        for(int j = 0; j < 2; j++) {
            m_arrOutKey[i][j] = 0;
        }
    }
    for(int i = 0; i < 2; i++) {
        m_arrBufKey[i] = 0;
    }
}

CDesOperate::~CDesOperate() {
	
}

INT32 CDesOperate::MakeKey ( ULONG32 *keyleft,ULONG32 *keyright ,ULONG32 number)
{
	ULONG32 tmpkey[2] ={0};
	ULONG32 *Ptmpkey = (ULONG32*)tmpkey;     
	ULONG32 *Poutkey = (ULONG32*)&m_arrOutKey[number]; 
	uint32_t leftandtab[3]={0x0,0x80000000,0xc0000000};
	INT32 j;        
	memset((ULONG8*)tmpkey,0,sizeof(tmpkey));          
	*Ptmpkey = *keyleft&leftandtab[lefttable[number]] ;           
	Ptmpkey[1] = *keyright&leftandtab[lefttable[number]] ;              
	if ( lefttable[number] == 1)
	{
		*Ptmpkey >>= 27;
		Ptmpkey[1] >>= 27;
	}
	else
	{
		*Ptmpkey >>= 26;
		Ptmpkey[1] >>= 26;                    
	}
	Ptmpkey[0] &= 0xfffffff0;
	Ptmpkey[1] &= 0xfffffff0;
	*keyleft <<= lefttable[number] ;
	*keyright <<= lefttable[number] ;
	*keyleft |= Ptmpkey[0] ;
	*keyright |= Ptmpkey[1] ;            
	Ptmpkey[0] = 0;
	Ptmpkey[1] = 0;
	for ( j = 0 ; j < 48 ; j++)
	{
		if ( j < 24 )
		{
			
			if ( *keyleft&pc_by_bit[keychoose[j]-1])
			{
				Poutkey[0] |= pc_by_bit[j] ;
			}                   
		}            
		else 
		{                   
			if ( *keyright&pc_by_bit[(keychoose[j]-28)])
			{
				Poutkey[1] |= pc_by_bit[j-24] ;
			}                   
		}
	}
	return SUCCESS;
}

INT32 CDesOperate::MakeData(uint32_t *left ,uint32_t *right ,uint32_t number){
    //保存右边段
    uint32_t oldright=*right;

     //用于接收扩展后的输出
    uint32_t exdes_P[2]={0};

    //用于接收压缩后的8个输出
    uint32_t rexpbuf[8]={0};

   
    int j ;

    //扩展运算
    for ( j = 0 ; j < 48 ; j++)
	{
		if ( j < 24 )
		{
			if ( *right&pc_by_bit[des_E[j]-1] )
			{
				exdes_P[0] |= pc_by_bit[j] ;
			}            
		}            
		else
		{
			if ( *right&pc_by_bit[des_E[j]-1] )
			{
				exdes_P[1] |= pc_by_bit[j-24] ;
			}
		}
	}

    //密钥加运算
    for ( j = 0 ; j < 2 ; j++)
	{            
		exdes_P[j] ^= m_arrOutKey[number][j] ;
	}


    //压缩操作
    exdes_P[1] >>= 8 ;
    rexpbuf[7] = (ULONG8) (exdes_P[1]&0x0000003fL) ;
	exdes_P[1] >>= 6 ;
	rexpbuf[6] = (ULONG8) (exdes_P[1]&0x0000003fL) ;
	exdes_P[1] >>= 6 ;
	rexpbuf[5] = (ULONG8) (exdes_P[1]&0x0000003fL) ;
	exdes_P[1] >>= 6 ;
	rexpbuf[4] = (ULONG8) (exdes_P[1]&0x0000003fL) ;
	exdes_P[0]  >>=  8 ;
	rexpbuf[3] = (ULONG8) (exdes_P[0]&0x0000003fL) ;     
	exdes_P[0] >>= 6 ;
	rexpbuf[2] = (ULONG8) (exdes_P[0]&0x0000003fL) ;
	exdes_P[0] >>= 6 ;
	rexpbuf[1] = (ULONG8) (exdes_P[0]&0x0000003fL) ;
	exdes_P[0] >>= 6 ;
	rexpbuf[0] = (ULONG8) (exdes_P[0]&0x0000003fL) ;     
	exdes_P[0] = 0 ;
	exdes_P[1] = 0 ;

    //置换操作
    *right = 0 ;
	for ( j = 0 ; j < 7 ; j++)
	{
		*right |= des_S[j][rexpbuf[j]] ;
		*right <<= 4 ;
	}
	*right |= des_S[j][rexpbuf[j]] ;
    uint32_t datatmp = 0;
	for ( j = 0 ; j < 32 ; j++)
	{
		if ( *right&pc_by_bit[des_P[j]-1] )
		{
			datatmp |= pc_by_bit[j] ;
		}
	}
	*right = datatmp ;

    //计算下一轮的左右段
    *right ^= *left;       
	*left = oldright;

    return true;

}

INT32 CDesOperate::HandleData(ULONG32 *left , ULONG8 choice){
    INT32  number = 0 ,j = 0;   
	ULONG32 *right = &left[1] ;
	ULONG32 tmp = 0;       
	ULONG32 tmpbuf[2] = { 0 };     

    //初始置换并分组
	for ( j = 0 ; j < 64 ; j++)
	{
		if (j < 32 ) 
		{
			if ( pc_first[j] > 32)
			{
				if ( *right&pc_by_bit[pc_first[j]-1] )
				{
					tmpbuf[0] |= pc_by_bit[j] ;
				}
			}
			else
			{
				if ( *left&pc_by_bit[pc_first[j]-1] )
				{
					tmpbuf[0] |= pc_by_bit[j] ;
				}
			}
		}
		else
		{
			if ( pc_first[j] > 32)
			{
				if ( *right&pc_by_bit[pc_first[j]-1] )
				{
					tmpbuf[1] |= pc_by_bit[j] ;
				}
			}
			else
			{
				if ( *left&pc_by_bit[pc_first[j]-1] )
				{
					tmpbuf[1] |= pc_by_bit[j] ;
				}
			}
		}
	}
	*left  = tmpbuf[0];
	*right = tmpbuf[1]; 
    tmpbuf[0] = 0;
    tmpbuf[1] = 0;


    //16轮迭代
    switch (choice)
    {
    case 0:
        for(int num = 0; num < 16; num++)
        {
            MakeData(left,right,(uint32_t)num);
        }
        break;
    case 1:
        for(int num = 15; num >= 0; num--)
        {
            MakeData(left,right,(uint32_t)num);
        }
        break;
    default:
        break;
    }


    //左右交换 ? 实验指导中没写？
    uint32_t temp = *left;
    *left = *right;
    *right = temp;

    //逆初始置换
    for ( j = 0 ; j < 64 ; j++)
	{
		if (j < 32 ) 
		{
			if ( pc_last[j] > 32)
			{
				if ( *right&pc_by_bit[pc_last[j]-1] )
				{
					tmpbuf[0] |= pc_by_bit[j] ;
				}
			}
			else
			{
				if ( *left&pc_by_bit[pc_last[j]-1] )
				{
					tmpbuf[0] |= pc_by_bit[j] ;
				}
			}
		}
		else
		{
			if ( pc_last[j] > 32)
			{
				if ( *right&pc_by_bit[pc_last[j]-1] )
				{
					tmpbuf[1] |= pc_by_bit[j] ;
				}
			}
			else
			{
				if ( *left&pc_by_bit[pc_last[j]-1] )
				{
					tmpbuf[1] |= pc_by_bit[j] ;
				}
			}
		}
	}
	*left =  tmpbuf[0] ;
	*right = tmpbuf[1];

    return true;
}

INT32 CDesOperate::Encry(char* pPlaintext,int nPlaintextLength,char *pCipherBuffer,int &nCipherBufferLength, char *pKey,int nKeyLength)
	{

        if(nKeyLength != 8)
        {
            return 0;
        }
        MakeFirstKey((ULONG32 *)pKey);
        int nLenthofLong = ((nPlaintextLength+7)/8)*2;
		if(nCipherBufferLength<nLenthofLong*4)
		{//out put buffer is not enough
			nCipherBufferLength=nLenthofLong*4;
			return 0;
		}
		memset(pCipherBuffer,0,nCipherBufferLength);
		ULONG32 *pOutPutSpace = (ULONG32 *)pCipherBuffer;
		ULONG32 * pSource;
		if(nPlaintextLength != sizeof(ULONG32)*nLenthofLong)
		{
			pSource= new ULONG32[nLenthofLong];
			memset(pSource,0,sizeof(ULONG32)*nLenthofLong);
			memcpy(pSource,pPlaintext,nPlaintextLength);
		}
		else		{
			pSource= (ULONG32 *)pPlaintext;
		}
        ULONG32 gp_msg[2] = {0,0};
		for (int i=0;i<(nLenthofLong/2);i++)
		{
			gp_msg[0] = pSource [2*i];
			gp_msg[1] = pSource [2*i+1];
			HandleData(gp_msg,DESENCRY);
			pOutPutSpace[2*i] = gp_msg[0];
			pOutPutSpace[2*i+1] = gp_msg[1];
		}
		if(pPlaintext!=(char *) pSource)
		{
			delete []pSource;
		}
	    
		return SUCCESS;
	}


INT32 CDesOperate::Decry(char* pCipher, int nCipherBufferLength, char *pPlaintextBuffer, int &nPlaintextBufferLength, char *pKey,int nKeyLength){
    if(nKeyLength != 8) {
        return 0;
    }
    MakeFirstKey((uint32_t *)pKey);

    memset(pPlaintextBuffer,0,nPlaintextBufferLength);
    uint32_t *pOutPutSpace = (uint32_t *)pPlaintextBuffer;
    uint32_t * pSource = (uint32_t *)pCipher;

    uint32_t gp_msg[2] = {0,0};
    for (int i=0;i<(nCipherBufferLength/8);i++) {
        gp_msg[0] = pSource [2*i];
        gp_msg[1] = pSource [2*i+1];
        HandleData(gp_msg,(uint8_t)1);
        pOutPutSpace[2*i] = gp_msg[0];
        pOutPutSpace[2*i+1] = gp_msg[1];
    }

    return true;
}

INT32 CDesOperate::MakeFirstKey(ULONG32 *keyP) {
    uint32_t tempKey[2]={0};
    uint32_t*pFirstKey=(uint32_t*)m_arrBufKey;
    uint32_t*pTempKey=(uint32_t*)tempKey;
    memset((uint8_t*)m_arrBufKey, 0, sizeof(m_arrBufKey));
    memcpy((uint8_t*)&tempKey, (uint8_t*)keyP,8);
    memset((uint8_t*)m_arrOutKey, 0, sizeof(m_arrOutKey));
    for(int j = 0; j < 28; j++) {                                                        
        
        if(keyleft[j] > 32)
        {                                                    
            if(pTempKey[1]&pc_by_bit[keyleft[j]-1]) {                                                
               
                pFirstKey[0] |= pc_by_bit[j];                                            
            }
        }                                                   
        
        else {
            if(pTempKey[0] & pc_by_bit[keyleft[j] - 1])
            {
                pFirstKey[0] |= pc_by_bit[j];
            }
        }
        if(keyright[j] > 32) {                                                    
            
            if(pTempKey[1] & pc_by_bit[keyright[j] - 1]) {
                pFirstKey[1] |= pc_by_bit[j];
            }
        }
        else {
            if(pTempKey[0] & pc_by_bit[keyright[j] - 1])
            {
                pFirstKey[1] |= pc_by_bit[j];
            }
        }
    }
    for(int j = 0; j < 16; j++) {
        MakeKey(&pFirstKey[0],&pFirstKey[1],j);          
    }
    return SUCCESS;
    
}