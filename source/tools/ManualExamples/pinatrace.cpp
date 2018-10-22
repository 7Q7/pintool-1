/*BEGIN_LEGAL 
Intel Open Source License 

Copyright (c) 2002-2018 Intel Corporation. All rights reserved.
 
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include "pin.H"


FILE * feature1RegMem;//��ͨ�üĴ����Լ��ڴ���ʵķ�ʽ����/д����
FILE * feature2InsIp;//��ǰָ���ŵĵ�ַ.�磺Ip:0x77125ab1 
FILE * feature3InsContent;//��ǰָ�����ݣ����������ʵ���Ӧ�Ĵ������ƣ���������Ϣ.
FILE * feature4Ins8Reg;//��ǰָ��ִ��ʱ��8��ͨ�üĴ�������.
FILE * feature5InsCR3;//���ƼĴ�����CR3������
FILE * feature6InsProcessID;//����ID
FILE * featureInsCount;//����ID

static UINT64 icount = 0;

// This function is called before every instruction is executed
VOID docount() { icount++; }

//---start feature2InsIp ��ӡipָ���ַ---
// Pin calls this function every time a new instruction is encountered 
VOID printip(VOID *ip) { fprintf(feature2InsIp, "ip: %p\n", ip); }
//===end ��ӡipָ���ַ ===

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{//ipΪָ����ڴ��ַ��ָ�����֣��漰���ļĴ�����addrΪָ��ķ��ʵ�ַ��
    fprintf(feature1RegMem,"R_mem: %p\n", addr);//��ָ��漰����8�ּĴ���
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{
    fprintf(feature1RegMem,"W_mem: %p\n", addr);//�ӼĴ���
}

//---start �Ĵ���������---
ADDRINT ReadReg(REG reg, ADDRINT * addr)
{
    //*out << "Emulate loading from addr " << addr << " to " << REG_StringShort(reg) << endl;
	fprintf(feature1RegMem,"R_reg: %p\n", REG_StringShort(reg));//�ӼĴ���
    ADDRINT value;
    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));//?
    return value;
}

ADDRINT WriteReg(REG reg, ADDRINT * addr)
{
    //*out << "Emulate loading from addr " << addr << " to " << REG_StringShort(reg) << endl;
	fprintf(feature1RegMem,"W_reg: %p\n", REG_StringShort(reg));//�ӼĴ���
    ADDRINT value;
    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));//?
    return value;
}
//===end �Ĵ���������===

//string 	LEVEL_CORE::INS_Disassemble (INS ins) �����ָ��.��ӡָ�����ݡ�


//---whz�ؼ����룺��ӡ�ڴ��ַ
VOID Instruction(INS ins, VOID *v)
{
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);//ͳ��ָ������
		
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);

	LOG(icount +" 0 INS_Disassemble :"+INS_Disassemble(ins)+"\n");
	LOG(icount +" 0 W_reg :"+REG_StringShort(INS_RegW(ins,0))+"\t\t\t R_reg :"+REG_StringShort(INS_RegR(ins,0))+"\n");
	//LOG(icount +" 1 W_reg :"+REG_StringShort(INS_RegW(ins,1))+"\t\t\t R_reg :"+REG_StringShort(INS_RegR(ins,1))+"\n");
	//LOG(icount +" 2 W_reg :"+REG_StringShort(INS_RegW(ins,2))+"\t\t\t R_reg :"+REG_StringShort(INS_RegR(ins,2))+"\n");
	LOG(icount +" --------------  \n");

    UINT32 memOperands = INS_MemoryOperandCount(ins);
	fprintf(featureInsCount,"icount: %d ,memOperands:%d \n",icount,memOperands);
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
		//LOG("INS_RegW :"+INS_RegW(ins,1)+"INS_RegR :"+INS_RegR(ins,1));
		//if(INS_Opcode(ins) != XED_ICLASS_MOV && 
		//	INS_IsMemoryRead(ins) && 
		//	IARG_RegR(ins, 0)){//regΪins�ĵ�0����������дreg
		//	INS_InsertCall(ins,
		//				   IPOINT_BEFORE,
		//				   AFUNPTR(WriteReg),
		//				   IARG_UINT32,
		//				   REG(INS_OperandReg(ins, 0)),//?
		//				   IARG_MEMORYREAD_EA,
		//				   IARG_RETURN_REGS,
		//				   INS_OperandReg(ins, 0),
		//				   IARG_END);
		//}
		//if(INS_Opcode(ins) != XED_ICLASS_MOV && 
		//	INS_IsMemoryRead(ins) && 
		//	INS_RegW(ins, 1)){//regΪins�ĵ�1������������reg
		//	INS_InsertCall(ins,
		//				   IPOINT_BEFORE,
		//				   AFUNPTR(ReadReg),
		//				   IARG_UINT32,
		//				   REG(INS_OperandReg(ins, 1)),//?
		//				   IARG_MEMORYREAD_EA,
		//				   IARG_RETURN_REGS,
		//				   INS_OperandReg(ins, 1),
		//				   IARG_END);
		//}
				 

        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be 
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }

    }
}

VOID Fini(INT32 code, VOID *v)
{
    fprintf(feature1RegMem, "#eof\n");
    fclose(feature1RegMem);

	fprintf(feature2InsIp, "#eof\n");
    fclose(feature2InsIp);

	fprintf(feature3InsContent, "#eof\n");
    fclose(feature3InsContent);

	fprintf(feature4Ins8Reg, "#eof\n");
    fclose(feature4Ins8Reg);

	fprintf(feature5InsCR3, "#eof\n");
    fclose(feature5InsCR3);

	fprintf(feature6InsProcessID, "#eof\n");
    fclose(feature6InsProcessID);

	fprintf(featureInsCount,"InsCount: %d \n",icount);
	fprintf(featureInsCount, "#eof\n");
    fclose(featureInsCount);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    PIN_ERROR( "This Pintool prints a feature1RegMem of memory addresses\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    feature1RegMem = fopen("feature1RegMem.out", "w");
	feature2InsIp = fopen("feature2InsIp.out", "w");
	feature3InsContent = fopen("feature3InsContent.out", "w");
	feature4Ins8Reg = fopen("feature4Ins8Reg.out", "w");
	feature5InsCR3 = fopen("feature5InsCR3.out", "w");
	feature6InsProcessID = fopen("feature6InsProcessID.out", "w");
	featureInsCount = fopen("featureInsCount.out", "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
