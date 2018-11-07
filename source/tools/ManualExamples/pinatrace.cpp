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
#include <stdlib.h>
// #include <unistd.h>   //getpid() current pid.eg:pid of hi.
#include "time.h"
#include "pin.H"
// using namespace std;

#define  MAX_INS_AFTER_SYS_CALL  500


FILE * feature1RegMem;//对通用寄存器以及内存访问的方式（读/写）。
FILE * feature2InsIp;//当前指令被存放的地址.如：Ip:0x77125ab1 
FILE * feature3InsContent;//当前指令内容，包括所访问的相应寄存器名称，操作码信息.
FILE * feature4Ins8Reg;//当前指令执行时的8个通用寄存器内容.IARG_REG_VALUE 
FILE * feature5InsCR3;//控制寄存器（CR3）内容
FILE * feature6InsProcessID;//进程ID
FILE * featureInsCount;//指令总数
FILE * featureAllInAFile;//所有特征在一个文件中
FILE * featureSyscall;//所有特征在一个文件中


static bool isSeparateFile = false;
static bool isDebug = true;
UINT64 icount = 0;
UINT32 numRRegs=0;
UINT32 numWRegs=0;

static int cntAfterSysEntered = 0;
static bool sysEnterFlag =false;

// std::vector<LEVEL_BASE::REG> vread_regs; // to do optizime reg in a line
// std::vector<LEVEL_BASE::REG> vwrite_regs;
// LEVEL_BASE::REG  readReg;
// LEVEL_BASE::REG  writeReg;
// string * readRegPointer;
// string * writeRegPointer;

void printTime(){
	time_t rawtime;
	struct tm * timeinfo;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	string timeStr = asctime(timeinfo);
	LOG(timeStr+"------ The current date/time is: %s \n");
}

VOID closeFile(){
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

	fprintf(featureInsCount,"InsCount: %d \n",(unsigned int)icount);
	fprintf(featureInsCount, "#eof\n");
	fclose(featureInsCount);

	fprintf(featureSyscall, "#eof\n");
	fclose(featureSyscall);
}

// This function is called before every instruction is executed
VOID docount() { icount++; }

//---start feature2InsIp 打印ip指令地址---
// Pin calls this function every time a new instruction is encountered 
VOID printip(VOID *ip) {  
	if(isDebug){
		LOG(decstr(icount)+",ip: "+ptrstr(ip)+"\n");
	}else{//非debug模式
		if(isSeparateFile){//每个特征以 单独的文件输出
			fprintf(feature2InsIp, "ip: %p\n", ip);
		}else{//所有特征以 同一个文件输出
			fprintf(featureAllInAFile, "ip: %p\n", ip);
		}
	}
}
//===end 打印ip指令地址 ===

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{//ip为指令的内存地址，指令名字，涉及到的寄存器，addr为指令的访问地址。
	if(isDebug){
		LOG(decstr(icount)+",R_mem: "+ptrstr(addr)+"\n");
	}else{//非debug模式
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
	}else{//非debug模式
		if(isSeparateFile){
			fprintf(feature1RegMem,"W_mem: %p\n", addr);
		}else{
			fprintf(featureAllInAFile,"W_mem: %p\n", addr);
		}
	}
}

VOID RecordInsStr(string * insPoniter)
{
	if(cntAfterSysEntered > MAX_INS_AFTER_SYS_CALL){
		LOG(decstr(icount)+",sysEnterFlag="+StringBool(sysEnterFlag)+",cntAfterSysEntered="+decstr(cntAfterSysEntered)+",icloseFile:   exit"+"\n");
		// closeFile();
		// exit(0);
	}
	if(sysEnterFlag == true){
		cntAfterSysEntered++;
	}
	
	if(isDebug){
		LOG(decstr(icount)+",sysEnterFlag="+StringBool(sysEnterFlag)+",cntAfterSysEntered="+decstr(cntAfterSysEntered)+",ins: "+insPoniter->c_str()+"\n");
	// }else{
		if(isSeparateFile){
			fprintf(feature3InsContent, "ins: %s\n", insPoniter->c_str());//特征3：原指令
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
	ADDRINT sp = PIN_GetContextReg( ctxt, REG_STACK_PTR);//REG_ESP
	//4 segment reg
	ADDRINT reg_seg_cs =PIN_GetContextReg( ctxt, REG_SEG_CS);
	ADDRINT reg_seg_ds =PIN_GetContextReg( ctxt, REG_SEG_DS);
	ADDRINT reg_seg_ss =PIN_GetContextReg( ctxt, REG_SEG_SS);
	ADDRINT reg_seg_es =PIN_GetContextReg( ctxt, REG_SEG_ES);
	//2 control reg
	ADDRINT reg_ip =PIN_GetContextReg( ctxt, REG_INST_PTR );// REG_INST_PTR = REG_EIP, 
	ADDRINT flags = PIN_GetContextReg(ctxt, REG_GFLAGS);

	if(isDebug){
		LOG(decstr(icount)+",EAX:"+StringFromAddrint(ax)+",EBX:"+StringFromAddrint(bx)+",ECX:"+StringFromAddrint(cx)+",EDX:"+StringFromAddrint(dx)
			+",ESI:"+StringFromAddrint(si)+",EDI:"+StringFromAddrint(di)+",EBP:"+StringFromAddrint(bp)+",ESP:"+StringFromAddrint(sp)
			+",reg_seg_cs:"+StringFromAddrint(reg_seg_cs)+",reg_seg_ds:"+StringFromAddrint(reg_seg_ds)
			+",reg_seg_ss:"+StringFromAddrint(reg_seg_ss)+",reg_seg_es:"+StringFromAddrint(reg_seg_es)
			+",reg_ip:"+StringFromAddrint(reg_ip)+",flags:"+StringFromAddrint(flags)+"\n");
	}else{
		if(isSeparateFile){
			fprintf(feature4Ins8Reg, "EAX:0x%16x EBX:0x%16x ECX:0x%16x EDX:0x%16x EBP:0x%16x ESP:0x%16x EDI:0x%16x ESI:0x%16x\n",
				(unsigned int)(long)ax,(unsigned int)(long)bx,(unsigned int)(long)cx,(unsigned int)(long)dx,
				(unsigned int)(long)bp,(unsigned int)(long)sp,(unsigned int)(long)di,(unsigned int)(long)si );
		}else{
			fprintf(featureAllInAFile,  "EAX:0x%16x EBX:0x%16x ECX:0x%16x EDX:0x%16x EBP:0x%16x ESP:0x%16x EDI:0x%16x ESI:0x%16x\n",
			(unsigned int)(long)ax,(unsigned int)(long)bx,(unsigned int)(long)cx,(unsigned int)(long)dx,
			(unsigned int)(long)bp,(unsigned int)(long)sp,(unsigned int)(long)di,(unsigned int)(long)si );
		}
	}
}

// VOID RecordCR3Content(const CONTEXT * ctxt)
VOID RecordCR3Content( CONTEXT * ctxt)
{
	ADDRINT reg_ax = PIN_GetContextReg( ctxt, REG_GAX );
	ADDRINT reg_cr0 = PIN_GetContextReg( ctxt, REG_CR0 );
	// ADDRINT cr4= PIN_GetContextReg( ctxt, REG_CR4 );
	// PIN_SetContextReg( ctxt, REG_CR3,0x80000000 );
	// https://software.intel.com/sites/landingpage/pintool/docs/97619/Pin/html/group__CONTEXT__API.html#ga2369ec2d95122f62cb3673a5a3507023
	//PIN_GetContextReg: Get the value of the integer register or fp status/control register in the specified context.
	ADDRINT cr3 = PIN_GetContextReg( ctxt, REG_CR3 );
	
	if(isDebug){
		LOG(decstr(icount)+",CR3:"+decstr(cr3)+",reg_ax:"+decstr(reg_ax)+",reg_cr0="+decstr(reg_cr0)+"\n");
		// LOG(decstr(icount)+",CR3:"+decstr(cr3)+"\n");
	// }else{
		if(isSeparateFile){
			fprintf(feature5InsCR3, "CR3: 0x%16x\n",(unsigned int)(long) cr3);//特征5：cr3寄存器  %04x 16进制
		}else{
			fprintf(featureAllInAFile, "CR3: 0x%16x\n",(unsigned int)(long)cr3);
		}
	}
}

//特征6：当前进程id
VOID Recordpid()
{	
	if(isDebug){
		LOG(decstr(icount)+", Recordpid() pid: "+decstr(PIN_GetPid())+"------------------- \n");
	}else{
		if(isSeparateFile){
			fprintf(feature6InsProcessID, "pid: %d\n", PIN_GetPid());
		}else{
			fprintf(featureAllInAFile, "pid: %d\n", PIN_GetPid());
		}
	}
}

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2,
               ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
// #if defined(TARGET_IA32)
    // On ia32, there are only 5 registers for passing system call arguments,
    // but mmap needs 6. For mmap on ia32, the first argument to the system call
    // is a pointer to an array of the 6 arguments
    // if (num == SYS_mmap)
    // {
        // ADDRINT * mmapArgs = &arg0;
        // arg0 = mmapArgs[0];
        // arg1 = mmapArgs[1];
        // arg2 = mmapArgs[2];
        // arg3 = mmapArgs[3];
        // arg4 = mmapArgs[4];
        // arg5 = mmapArgs[5];
    // }
// #endif

	sysEnterFlag=true;

    	if(isDebug){
		LOG(decstr(icount)+",SysBefore()******  ip:0x"+decstr(ip)+",PIN_GetSyscallNumber="+decstr(num) +",arg0="+decstr(arg0)+",arg1="+decstr(arg1) +
			",arg2="+decstr(arg2) +",arg3="+decstr(arg3) +",arg4="+decstr(arg4) +",arg5="+decstr(arg5)  +"\n");
	}else{
		if(isSeparateFile){
			fprintf(featureSyscall, "SysBefore()  ip 0x%016x  , syscallnum=%d   arg=( 0x%016x  0x%016x  0x%x  0x%016x 0x%016x  0x%016x)  \n",
				 (unsigned int)(long)ip,  (unsigned int)(long)num,   (unsigned int)(long)arg0,   (unsigned int)(long)arg1,  
				 (unsigned int)(long)arg2,  (unsigned int)(long)arg3,  (unsigned int)(long)arg4,  (unsigned int)(long)arg5);
		}else{
			fprintf(featureAllInAFile, "SysBefore()  ip 0x%016x  , syscallnum=%d   arg=( 0x%016x  0x%016x  0x%x  0x%016x 0x%016x  0x%016x)  \n",
				 (unsigned int)(long)ip,  (unsigned int)(long)num,   (unsigned int)(long)arg0,   (unsigned int)(long)arg1,  
				 (unsigned int)(long)arg2,  (unsigned int)(long)arg3,  (unsigned int)(long)arg4,  (unsigned int)(long)arg5);
		}
	}


}


// Print the return value of the system call
VOID SysAfter( ADDRINT sysRetVal, INT32 sysErrNo, ADDRINT gax )
{  //sysRetVal:PIN_GetSyscallReturn()....sysErrNo:PIN_GetSyscallErrno()
    int error = 0;
    ADDRINT neg_one = (ADDRINT)(0-1);
    // sysEntered=false;

    if ( sysErrNo == 0 )//the error code==0, if the system call succeeded
    {
        if ( gax != sysRetVal )//reg_ax != PIN_GetSyscallReturn
            error = 1;//尽管PIN_GetSyscallErrno()==0但reg_ax != PIN_GetSyscallReturn (syscall返回值放在ax中).也认为failure. set error = 1
    }
    else
    {
        if ( sysRetVal != neg_one )//PIN_GetSyscallReturn() != -1
            error = 3;
        if ( sysErrNo != -(INT32)gax ) //PIN_GetSyscallErrno() != -rax
            error = 4;
    }

    if ( error == 0 )
        	if(isDebug){
		LOG(decstr(icount)+",  SysAfter()********  sysRetVal:"+decstr(sysRetVal)+",sysErrNo="+decstr(sysErrNo) +"\n");
	}else{
		if(isSeparateFile){
			        fprintf(featureSyscall, "  SysAfter()*********  success: PIN_GetSyscallReturn()  :  0x%016x  , PIN_GetSyscallErrno :  %d\n ",
					 (unsigned int)(long)sysRetVal,                                        sysErrNo);
		}else{
			        fprintf(featureAllInAFile, "   SysAfter()********* faliure: PIN_GetSyscallReturn()  :  0x%016x  , PIN_GetSyscallErrno :  %d\n ",
					 (unsigned int)(long)sysRetVal,                                        sysErrNo);
		}
	}

    else {
    	 if(isDebug){
		LOG(decstr(icount)+",  SysAfter()  sysRetVal:"+decstr(sysRetVal)+",sysErrNo="+decstr(sysErrNo) +"\n");
	}else{
		if(isSeparateFile){
			        fprintf(featureSyscall, "  SysAfter()----- success: PIN_GetSyscallReturn()  :  0x%016x  , PIN_GetSyscallErrno :  %d\n ",
					 (unsigned int)(long)sysRetVal,                                        sysErrNo);
		}else{
			        fprintf(featureAllInAFile, "  SysAfter()-----  faliure: PIN_GetSyscallReturn()  :  0x%016x  , PIN_GetSyscallErrno :  %d\n ",
					 (unsigned int)(long)sysRetVal,                                        sysErrNo);
		}
	}
     
    }

}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	// LOG(decstr(icount)+",  SyscallEntry()  threadIndex:"+decstr(threadIndex)+",PIN_GetTid ()="+decstr(PIN_GetTid ())+", getpid()="+ decstr(getpid())+"\n");

    SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
        PIN_GetSyscallNumber(ctxt, std),//Get the number (ID) of the system call 
        PIN_GetSyscallArgument(ctxt, std, 0),//before the system call execution
        PIN_GetSyscallArgument(ctxt, std, 1),
        PIN_GetSyscallArgument(ctxt, std, 2),
        PIN_GetSyscallArgument(ctxt, std, 3),
        PIN_GetSyscallArgument(ctxt, std, 4),
        PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	// LOG(decstr(icount)+",  SyscallExit()  threadIndex:"+decstr(threadIndex)+",PIN_GetTid ()="+decstr(PIN_GetTid ())+"\n");

    SysAfter(PIN_GetSyscallReturn(ctxt, std),
             PIN_GetSyscallErrno(ctxt, std),
             PIN_GetContextReg(ctxt, REG_GAX));//REG_GAX = REG_EAX, 
}

//---whz关键代码：打印内存地址
VOID Instruction(INS ins, VOID *v)
{
	if(isDebug){
		INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);//统计指令条数
	}

	//-----特征4 start-当前指令执行时的8个通用寄存器内容----iarg_reg_value 
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Record8RegContent,IARG_CONTEXT, IARG_END);//特征4
	//=====特征4 end=======================

	//------特征3 start--汇编指令的内容 输入到feature3InsContent 文件。
	string * insPoniter = new string(INS_Disassemble(ins));
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordInsStr,IARG_PTR, insPoniter, IARG_END);//特征3
	//===特征3 end=======================

	//------feature 1 start-----
	for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); i++)
	{
		string *str = new string(REG_StringShort(INS_RegR(ins, i)));
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordReadReg,
			IARG_PTR, str,
			IARG_END);
	}
	
	for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); i++)
	{
		string *str = new string(REG_StringShort(INS_RegW(ins, i)));
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteReg,
			IARG_PTR, str,
			IARG_END);
	} 
	//------feature 1 end-----


	// Instruments memory accesses using a predicated call, i.e.
	 // the instrumentation is called iff the instruction will actually be executed.
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

	//---特征5  CR3寄存器内容--
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordCR3Content,IARG_CONTEXT, IARG_END);//特征5
	//===特征5 end=======================

	//---特征6 进程id--
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)Recordpid, IARG_END);//特征6
	//===特征6 end=======================
}



VOID Fini(INT32 code, VOID *v)
{
	closeFile();
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
	string file_name_prefix = string(argv[argc-1])+"_";

	featureSyscall = fopen( (file_name_prefix+"featureSyscall.out").c_str(), "w");
	feature1RegMem = fopen((file_name_prefix+"feature1RegMem.out").c_str(), "w");
	feature2InsIp = fopen((file_name_prefix+"feature2InsIp.out").c_str(), "w");
	feature3InsContent = fopen((file_name_prefix+"feature3InsContent.out").c_str(), "w");
	feature4Ins8Reg = fopen((file_name_prefix+"feature4Ins8Reg.out").c_str(), "w");
	feature5InsCR3 = fopen((file_name_prefix+"feature5InsCR3.out").c_str(), "w");
	feature6InsProcessID = fopen((file_name_prefix+"feature6InsProcessID.out").c_str(), "w");
	featureInsCount = fopen((file_name_prefix+"featureInsCount.out").c_str(), "w");
	featureAllInAFile = fopen((file_name_prefix+"featureAllInAFile.out").c_str(), "w");

	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);
	PIN_AddFiniFunction(Fini, 0);

    // Never returns
	PIN_StartProgram();

	return 0;
}