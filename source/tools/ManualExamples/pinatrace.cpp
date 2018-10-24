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


FILE * feature1RegMem;//对通用寄存器以及内存访问的方式（读/写）。
FILE * feature2InsIp;//当前指令被存放的地址.如：Ip:0x77125ab1 
FILE * feature3InsContent;//当前指令内容，包括所访问的相应寄存器名称，操作码信息.
FILE * feature4Ins8Reg;//当前指令执行时的8个通用寄存器内容.IARG_REG_VALUE 
FILE * feature5InsCR3;//控制寄存器（CR3）内容
FILE * feature6InsProcessID;//进程ID
FILE * featureInsCount;//指令总数

UINT64 icount = 0;
static string INVALID_REG = "*invalid*";
string insStr;
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

//---start feature2InsIp 打印ip指令地址---
// Pin calls this function every time a new instruction is encountered 
VOID printip(VOID *ip) { fprintf(feature2InsIp, "ip: %p\n", ip); }
//===end 打印ip指令地址 ===

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{//ip为指令的内存地址，指令名字，涉及到的寄存器，addr为指令的访问地址。
    fprintf(feature1RegMem,"R_mem: %p\n", addr);
	if(isDebug){
		LOG(decstr(icount)+",R_mem: "+ptrstr(addr)+"\n");
	}
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{
    fprintf(feature1RegMem,"W_mem: %p\n", addr);//加寄存器
	if(isDebug){
		LOG(decstr(icount)+",W_mem: "+ptrstr(addr)+"\n");
	}
}

////---start 寄存器的名字---
//ADDRINT ReadReg(REG reg, ADDRINT * addr)
//{
//    //*out << "Emulate loading from addr " << addr << " to " << REG_StringShort(reg) << endl;
//	fprintf(feature1RegMem,"R_reg: %p\n", REG_StringShort(reg));//加寄存器
//    ADDRINT value;
//    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));//?
//    return value;
//}
//
//ADDRINT WriteReg(REG reg, ADDRINT * addr)
//{
//    //*out << "Emulate loading from addr " << addr << " to " << REG_StringShort(reg) << endl;
//	fprintf(feature1RegMem,"W_reg: %p\n", REG_StringShort(reg));//加寄存器
//    ADDRINT value;
//    PIN_SafeCopy(&value, addr, sizeof(ADDRINT));//?
//    return value;
//}
////===end 寄存器的名字===

VOID RecordInsStr(string * insPoniter)
{
	fprintf(feature3InsContent, "a: %s\n", insPoniter->c_str());//特征3：原指令
	if(isDebug){
		LOG(decstr(icount)+",a: "+insPoniter->c_str()+"\n");
	}
}

VOID RecordReadReg(string * readRegPointer)
{
	fprintf(feature1RegMem, "R_reg: %s\n", readRegPointer->c_str());//特征1：读入的寄存器
	if(isDebug){
		LOG(decstr(icount)+",R_reg :"+readRegPointer->c_str()+"\n");
	}
}

VOID RecordWriteReg(string * writeRegPointer)
{
	fprintf(feature1RegMem, "W_reg: %s\n", writeRegPointer->c_str());//特征1：读入的寄存器
	if(isDebug){
		LOG(decstr(icount)+",W_reg :"+writeRegPointer->c_str()+"\n");
	}
}

VOID Record8RegContent(const CONTEXT * ctxt)
{
		//ADDRINT reg_ip =PIN_GetContextReg( ctxt, REG_INST_PTR );
	ADDRINT ax = PIN_GetContextReg( ctxt, REG_GAX );
	ADDRINT bx = PIN_GetContextReg( ctxt, REG_GBX );
	ADDRINT cx = PIN_GetContextReg( ctxt, REG_GCX );
	ADDRINT dx = PIN_GetContextReg( ctxt, REG_GDX );
	ADDRINT si = PIN_GetContextReg( ctxt, REG_GSI );
	ADDRINT di = PIN_GetContextReg( ctxt, REG_GDI );
	ADDRINT bp = PIN_GetContextReg( ctxt, REG_GBP );
	ADDRINT sp = PIN_GetContextReg( ctxt, REG_ESP );
	//ADDRINT flags = PIN_GetContextReg(ctxt, REG_GFLAGS); //

	fprintf(feature4Ins8Reg, "EAX:%d EBX:%d ECX:%d EDX:%d EBP:%d ESP:%d EDI:%d ESI:%d\n", ax,bx,cx,dx,si,di,bp,sp);//特征1：读入的寄存器
	if(isDebug){
		LOG(decstr(icount)+",EAX:"+decstr(ax)+",EBX:"+decstr(bx)+",ECX:"+decstr(cx)+",EDX:"+decstr(dx)
			+",ESI:"+decstr(si)+",EDI:"+decstr(di)+",EBP:"+decstr(bp)+",ESP"+decstr(sp)+"\n");
	}
}

VOID RecordCR3Content(const CONTEXT * ctxt)
{
	ADDRINT cr3 = PIN_GetContextReg( ctxt, REG_CR3 );
	fprintf(feature5InsCR3, "CR3:%d\n", cr3);//特征5：cr3寄存器
	if(isDebug){
		LOG(decstr(icount)+",cr3:"+decstr(cr3)+"\n");
	}
}

VOID Recordpid()
{
	fprintf(feature6InsProcessID, "ID:%d\n", PIN_GetPid());//特征6：当前进程id
	if(isDebug){
		LOG(decstr(icount)+",ID:"+decstr(PIN_GetPid())+"\n");
	}
}

//---whz关键代码：打印内存地址
VOID Instruction(INS ins, VOID *v)
{
	if(isDebug){
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);//统计指令条数
	}
	//------特征1 start-----
	string * readRegPointer = new string(REG_StringShort(INS_RegR(ins,0)));
	string * writeRegPointer = new string(REG_StringShort(INS_RegW(ins,0)));
	if(readRegPointer->c_str() != INVALID_REG)
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordReadReg,IARG_PTR, readRegPointer, IARG_END);//特征1：读入的寄存器
	}
	if(writeRegPointer->c_str() != INVALID_REG)
	{
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteReg,IARG_PTR, writeRegPointer, IARG_END);//特征1：写入的寄存器
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
	//===特征1 end========================

	//------特征2 start-----：指令存放的ip地址
	INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);//特征2
	//===特征2 end========================

	//------特征3 start--汇编指令的内容 输入到文件。
	string * insPoniter = new string(INS_Disassemble(ins));
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInsStr,IARG_PTR, insPoniter, IARG_END);//特征3
	//===特征3 end=======================

	//-----特征4 start-当前指令执行时的8个通用寄存器内容----IARG_REG_VALUE 
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Record8RegContent,IARG_CONTEXT, IARG_END);//特征4
	//=====特征4 end=======================

	//---特征5  CR3寄存器内容--
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordCR3Content,IARG_CONTEXT, IARG_END);//特征5
	//===特征5 end=======================

	//---特征6 进程id--
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Recordpid, IARG_END);//特征5
	//===特征6 end=======================
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
