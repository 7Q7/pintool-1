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
#include "time.h"
#include "pin.H"


FILE * feature1RegMem;//��ͨ�üĴ����Լ��ڴ���ʵķ�ʽ����/д����
FILE * feature2InsIp;//��ǰָ���ŵĵ�ַ.�磺Ip:0x77125ab1 
FILE * feature3InsContent;//��ǰָ�����ݣ����������ʵ���Ӧ�Ĵ������ƣ���������Ϣ.
FILE * feature4Ins8Reg;//��ǰָ��ִ��ʱ��8��ͨ�üĴ�������.IARG_REG_VALUE 
FILE * feature5InsCR3;//���ƼĴ�����CR3������
FILE * feature6InsProcessID;//����ID
FILE * featureInsCount;//ָ������
FILE * featureAllInAFile;//����������һ���ļ���

UINT64 icount = 0;
static string INVALID_REG = "*invalid*";
string insStr;
static bool isSeparateFile = false;
static bool isDebug = true;

void printTime(){
	time_t rawtime;
	struct tm * timeinfo;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	string timeStr = asctime(timeinfo);
	LOG(timeStr+"------ The current date/time is: %s \n");
}


// This function is called before every instruction is executed
VOID docount() { icount++; }

//---start feature2InsIp ��ӡipָ���ַ---
// Pin calls this function every time a new instruction is encountered 
VOID printip(VOID *ip) {  
	if(isDebug){
		LOG(decstr(icount)+",ip: "+ptrstr(ip)+"\n");
	}else{//��debugģʽ
		if(isSeparateFile){//ÿ�������� �������ļ����
			fprintf(feature2InsIp, "ip: %p\n", ip);
		}else{//���������� ͬһ���ļ����
			fprintf(featureAllInAFile, "ip: %p\n", ip);
		}
	}
}
//===end ��ӡipָ���ַ ===

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{//ipΪָ����ڴ��ַ��ָ�����֣��漰���ļĴ�����addrΪָ��ķ��ʵ�ַ��
	if(isDebug){
		LOG(decstr(icount)+",R_mem: "+ptrstr(addr)+"\n");
	}else{//��debugģʽ
		if(isSeparateFile){
			fprintf(feature1RegMem,"R_mem: %p\n", addr);
		}else{
			fprintf(featureAllInAFile,"R_mem: %p\n", addr);
		}
	}
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{

	if(isDebug){
		LOG(decstr(icount)+",W_mem: "+ptrstr(addr)+"\n");
	}else{//��debugģʽ
		if(isSeparateFile){
			fprintf(feature1RegMem,"W_mem: %p\n", addr);
		}else{
			fprintf(featureAllInAFile,"W_mem: %p\n", addr);
		}
	}
}

////---start �Ĵ���������---
//ADDRINT ReadReg(REG reg, ADDRINT * addr)
//{
//    //*out << "Emulate loading from addr " << addr << " to " << REG_StringShort(reg) << endl;
//	fprintf(feature1RegMem,"R_reg: %p\n", REG_StringShort(reg));//�ӼĴ���
//    ADDRINT value;
//    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));//?
//    return value;
//}
//
//ADDRINT WriteReg(REG reg, ADDRINT * addr)
//{
//    //*out << "Emulate loading from addr " << addr << " to " << REG_StringShort(reg) << endl;
//	fprintf(feature1RegMem,"W_reg: %p\n", REG_StringShort(reg));//�ӼĴ���
//    ADDRINT value;
//    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));//?
//    return value;
//}
////===end �Ĵ���������===

VOID RecordInsStr(string * insPoniter)
{

	if(isDebug){
		LOG(decstr(icount)+",ins: "+insPoniter->c_str()+"\n");
	}else{
		if(isSeparateFile){
			fprintf(feature3InsContent, "ins: %s\n", insPoniter->c_str());//����3��ԭָ��
		}else{
			fprintf(featureAllInAFile, "ins: %s\n", insPoniter->c_str());
		}
	}
}

VOID RecordReadReg(string * readRegPointer)
{
	if(isDebug){
		LOG(decstr(icount)+",R_reg :"+readRegPointer->c_str()+"\n");
	}else{
		if(isSeparateFile){
			fprintf(feature1RegMem, "R_reg: %s\n", readRegPointer->c_str());
		}else{
			fprintf(featureAllInAFile, "R_reg: %s\n", readRegPointer->c_str());
		}
	}
}

VOID RecordWriteReg(string * writeRegPointer)
{
	if(isDebug){
		LOG(decstr(icount)+",W_reg :"+writeRegPointer->c_str()+"\n");
	}else{
		if(isSeparateFile){
			fprintf(feature1RegMem, "W_reg: %s\n", writeRegPointer->c_str());
		}else{
			fprintf(featureAllInAFile,"W_reg: %s\n", writeRegPointer->c_str());
		}
	}
}

VOID Record8RegContent(const CONTEXT * ctxt)
{//8 univsal reg
	ADDRINT ax = PIN_GetContextReg( ctxt, REG_GAX );
	ADDRINT bx = PIN_GetContextReg( ctxt, REG_GBX );
	ADDRINT cx = PIN_GetContextReg( ctxt, REG_GCX );
	ADDRINT dx = PIN_GetContextReg( ctxt, REG_GDX );
	ADDRINT si = PIN_GetContextReg( ctxt, REG_GSI );
	ADDRINT di = PIN_GetContextReg( ctxt, REG_GDI );
	ADDRINT bp = PIN_GetContextReg( ctxt, REG_GBP );
	ADDRINT sp = PIN_GetContextReg( ctxt, REG_ESP );
	//4 segment reg
	ADDRINT reg_seg_cs =PIN_GetContextReg( ctxt, REG_SEG_CS);
	ADDRINT reg_seg_ds =PIN_GetContextReg( ctxt, REG_SEG_DS);
	ADDRINT reg_seg_ss =PIN_GetContextReg( ctxt, REG_SEG_SS);
	ADDRINT reg_seg_es =PIN_GetContextReg( ctxt, REG_SEG_ES);
	//2 control reg
	ADDRINT reg_ip =PIN_GetContextReg( ctxt, REG_INST_PTR );
	ADDRINT flags = PIN_GetContextReg(ctxt, REG_GFLAGS);

	if(isDebug){
		LOG(decstr(icount)+",EAX:"+StringFromAddrint(ax)+",EBX:"+StringFromAddrint(bx)+",ECX:"+StringFromAddrint(cx)+",EDX:"+StringFromAddrint(dx)
			+",ESI:"+StringFromAddrint(si)+",EDI:"+StringFromAddrint(di)+",EBP:"+StringFromAddrint(bp)+",ESP:"+StringFromAddrint(sp)+

			",EAX:"+StringFromAddrint(ax)+",EBX:"+StringFromAddrint(bx)+",ECX:"+StringFromAddrint(cx)+",EDX:"+StringFromAddrint(dx)+

			",reg_ip:"+StringFromAddrint(bp)+",flags:"+StringFromAddrint(flags)+"\n");
	//}else{
		if(isSeparateFile){
			//fprintf(feature4Ins8Reg, "EAX:%d EBX:%d ECX:%d EDX:%d EBP:%d ESP:%d EDI:%d ESI:%d\n", ax,bx,cx,dx,si,di,bp,sp);
			fprintf(feature4Ins8Reg, "EAX:0x%08x EBX:0x%08x ECX:0x%08x EDX:0x%08x EBP:0x%08x ESP:0x%08x EDI:0x%08x ESI:0x%08x\n", 
				ax,bx,cx,dx,si,di,bp,sp);
		}else{
			fprintf(featureAllInAFile,  "EAX:0x%08x EBX:0x%08x ECX:0x%08x EDX:0x%08x EBP:0x%08x ESP:0x%08x EDI:0x%08x ESI:0x%08x\n", 
				ax,bx,cx,dx,si,di,bp,sp);
		}
	}
}

VOID RecordCR3Content(const CONTEXT * ctxt)
{
	ADDRINT cr3 = PIN_GetContextReg( ctxt, REG_CR3 );
	
	if(isDebug){
		LOG(decstr(icount)+",CR3:"+decstr(cr3)+"\n");
	}else{
		if(isSeparateFile){
			fprintf(feature5InsCR3, "CR3: 0x%08x\n", cr3);//����5��cr3�Ĵ���  %08x 16����
		}else{
			fprintf(featureAllInAFile, "CR3: 0x%08x\n", cr3);
		}
	}
}

//����6����ǰ����id
VOID Recordpid()
{	
	if(isDebug){
		LOG(decstr(icount)+",pid: "+decstr(PIN_GetPid())+"------------------- \n");
	}else{
		if(isSeparateFile){
			fprintf(feature6InsProcessID, "pid: %d\n", PIN_GetPid());
		}else{
			fprintf(featureAllInAFile, "pid: %d\n", PIN_GetPid());
		}
	}
}

//---whz�ؼ����룺��ӡ�ڴ��ַ
VOID Instruction(INS ins, VOID *v)
{
	if(isDebug){
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);//ͳ��ָ������
	}

	//-----����4 start-��ǰָ��ִ��ʱ��8��ͨ�üĴ�������----iarg_reg_value 
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Record8RegContent,IARG_CONTEXT, IARG_END);//����4
	//=====����4 end=======================

	//------����3 start--���ָ������� ���뵽feature3InsContent �ļ���
	string * insPoniter = new string(INS_Disassemble(ins));
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInsStr,IARG_PTR, insPoniter, IARG_END);//����3
	//===����3 end=======================

	//------����1 start-----
	string * readRegPointer = new string(REG_StringShort(INS_RegR(ins,0)));
	string * writeRegPointer = new string(REG_StringShort(INS_RegW(ins,0)));
	if(readRegPointer->c_str() != INVALID_REG)
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordReadReg,IARG_PTR, readRegPointer, IARG_END);
	}
	if(writeRegPointer->c_str() != INVALID_REG)
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteReg,IARG_PTR, writeRegPointer, IARG_END);//����1��д��ļĴ���
	}

	// Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);
	if(isDebug){
		LOG(decstr(icount)+",memOperands="+ decstr(memOperands)+" -----------------  \n ");
	}

    for (UINT32 memOp = 0; memOp < memOperands; memOp++){

        if (INS_MemoryOperandIsRead(ins, memOp)){
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
	//===����1 end========================

	//------����2 start-----��ָ���ŵ�ip��ַ
	INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);//����2
	//===����2 end========================

	//---����5  CR3�Ĵ�������--
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordCR3Content,IARG_CONTEXT, IARG_END);//����5
	//===����5 end=======================

	//---����6 ����id--
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Recordpid, IARG_END);//����6
	//===����6 end=======================
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

	fprintf(featureAllInAFile, "#eof\n");
	fclose(featureAllInAFile);

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
	featureAllInAFile = fopen("featureAllInAFile.out", "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
