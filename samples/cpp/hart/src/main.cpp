/*
 * Copyright (c) 2023, Meta
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <iostream>

#include "pthread.h"
#include "mqueue.h"
#include "signal.h"

#include "appconnector.h"
#include "nativeapp.h"
#include "tppdu.h"
#include "datatypes.h"

#include "hssems.h"
#include "hsudp.h"
#include "hsthreads.h"
#include "hsqueues.h"
#include "toolthreads.h"
#include "serverstate.h"

template<> bool AppConnector<AppPdu>::time2stop = false;
// FILE *p_toolLogPtr = NULL;
static uint16_t portNum = 5094;
enum AppState eAppState = APP_STOP;

pthread_t popRxThrID;  // used by Server to read msg from APP
pthread_t popTxThrID;  // used by APP to read msg from Server
pthread_t socketThrID; // used by Server to read socket
pthread_t appThrID = 0; // used by Server to launch the APP program

// template <AppPdu>
// uint16_t AppConnector<AppPdu>::getStats(uint16_t &stxs, uint16_t &acks, uint16_t &baks)
// {
// 	return 0;
// }

int signal(int signum, void (*_sig_func_ptr)(int))
{
	return 0;
}

int raise(int sig)
{
	return 0;
}

AppConnector<AppPdu> *pAppConnector = NULL;
//App *pGlobalApp = NULL;
NativeApp *pGlobalApp = NULL;

// uint8_t *TpPdu::DataBytes()
// {
//   // get index of data field
//   uint8_t index = IsLongFrame() ? TP_OFFSET_DATA_UNIQ : TP_OFFSET_DATA_POLL;

//   // correct it for RC+STATUS
//   index = IsSTX() ? index : index+2;

//   return &pPDU[index];
// }

// void TpPdu::SetByteCount(uint8_t bc)
// {
// 	int bcindex = (IsLongFrame()) ? TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

// 	pPDU[bcindex] = bc;
// }

// uint8_t *TpPdu::Delim()
// {
// 	uint8_t *p_delim = &(pPDU[TP_OFFSET_DELIM]);
// 	return p_delim;
// }

// bool TpPdu::IsLongFrame()
// {
// 	bool longframe = (TPDELIM_ADDR_MASK & *Delim()) == TPDELIM_ADDR_MASK;
// 	return longframe;
// }

// bool TpPdu::AddressMatch(const uint8_t *a)
// {
// 	int len = AddressLen();
// 	uint8_t buf1[TPHDR_ADDRLEN_UNIQ];
// 	uint8_t buf2[TPHDR_ADDRLEN_UNIQ];
// 	memcpy_s(buf1, TPHDR_ADDRLEN_UNIQ, Address(), len);
// 	memcpy_s(buf2, TPHDR_ADDRLEN_UNIQ, a, len);

// 	//// mask off primary master bit
// 	// buf1[0] &= 0x7f;
// 	// buf2[0] &= 0x7f;
// 	//  mask off primary master bit AND burst mode bit
// 	buf1[0] &= 0x3f;
// 	buf2[0] &= 0x3f;

// 	bool match = (memcmp(buf1, buf2, AddressLen()) == 0);
// 	return match;
// }

// void TpPdu::ProcessErrResponse(uint8_t rc)
// {

// }

// uint8_t *TpPdu::Address()
// {
// 	uint8_t *address = &pPDU[TP_OFFSET_ADDR];
// 	return address;
// }

// void TpPdu::InsertCheckSum()
// {
// 	int len = TotalLength() - 1;     // -1 convert counting number to index
// 	pPDU[len] = CheckSum(pPDU, len); // checksum doesn't include the checksum byte
// }

// uint16_t TpPdu::CmdNum()
// {
// 	int index = IsLongFrame() ? TP_OFFSET_CMD_UNIQ : TP_OFFSET_CMD_POLL;
// 	uint32_t cmd = pPDU[index];
// 	if (HART_CMD_EXP_FLAG == cmd) {
// 		int minbc = IsSTX() ? 0 : 2;

// 		if (ByteCount() > minbc) {
// 			// get index of expanded cmd #
// 			index = IsLongFrame() ? TP_OFFSET_DATA_UNIQ : TP_OFFSET_DATA_POLL;

// 			// correct it for RC+STATUS
// 			index = IsSTX() ? index : index + 2;

// 			cmd = (pPDU[index] << 8) + pPDU[index + 1];
// 		} else {
// 			// no data bytes => leave command number as 31
// 		}
// 	}

// 	return cmd;
// }

errVal_t NativeApp::getLowMAC(uint8_t *pArr, bool getFullAddress)
{
	return 0;
}

// uint8_t TpPdu::ResponseCode()
// {
// 	int bcindex = (IsLongFrame()) ? TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

// 	return pPDU[bcindex + 1]; // response code next byte past byte count
// }

// uint8_t TpPdu::TotalLength()
// {
// 	int bcindex;
// 	// index number of the Byte Count byte, adjusted for address length
// 	bcindex = (IsLongFrame()) ? TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

// 	//  delim     1 or 5 addr       cmd  BC  DATA        CHK
// 	//  xx		xx xx xx xx xx     xx  xx  xxxxxxxxxx  xx
// 	//  BC is number of bytes in the DATA section

// 	int bc = pPDU[bcindex];
// 	bcindex += 1; // convert index to counting number (length thru BC)

// 	// length thru byte count, + data + chcksum
// 	int len = bcindex + bc + 1; // +1 (checksum)

// 	return len; // number of bytes in the pdu
// }

// uint8_t TpPdu::ByteCount()
// {
// 	int bcindex = (IsLongFrame()) ? TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

// 	return pPDU[bcindex];
// }

// uint8_t TpPdu::AddressLen()
// {
// 	uint8_t addresslen = IsLongFrame() ? TPHDR_ADDRLEN_UNIQ : TPHDR_ADDRLEN_POLL;
// 	return addresslen;
// }

// uint8_t *TpPdu::RequestBytes()
// {
// 	return IsExpCmd() ? (DataBytes() + 2) : DataBytes();
// }

// uint8_t TpPdu::CheckSum(uint8_t *p, uint8_t plen)
// {
// 	uint8_t i;
// 	uint8_t chkSum = 0;

// 	for (i = 0; i < plen; i++) {
// 		chkSum ^= p[i];
// 	}

// 	return (chkSum);
// }

// bool TpPdu::IsExpCmd()
// {
// 	int index = IsLongFrame() ? TP_OFFSET_CMD_UNIQ : TP_OFFSET_CMD_POLL;
// 	uint32_t cmd = pPDU[index];
// 	return (HART_CMD_EXP_FLAG == cmd);
// }

// uint8_t TpPdu::RequestByteCount()
// {
// 	return IsExpCmd() ? (ByteCount() - 2) : ByteCount();
// }

// void print_to_both(FILE *p_log, const char *format, ...)
// {
// 	va_list args;
// 	va_start(args, format);
// 	vprintf(format, args);
// 	va_end(args);
// }

// void TpPdu::setCommandNumber(uint16_t newCmd)
// {
// 	int cindex = (IsLongFrame()) ? TP_OFFSET_CMD_UNIQ : TP_OFFSET_CMD_POLL;

// 	if (newCmd < 256) {
// 		pPDU[cindex] = newCmd;
// 	} else // has to be  < 65536 due to 16 bit cmd# in
// 	{
// 		pPDU[cindex] = HART_CMD_EXP_FLAG;

// 		// get index of expanded cmd #, corrected for RC & DEVSTAT
// 		cindex = 2 + (IsLongFrame() ? TP_OFFSET_DATA_UNIQ : TP_OFFSET_DATA_POLL);
// 		pPDU[cindex] = (uint8_t)(newCmd & 0xff);
// 		pPDU[cindex + 1] = (uint8_t)((newCmd >> 8) & 0xff);
// 	}
// }

// uint8_t *TpPdu::ResponseBytes()
// {
// 	return RequestBytes(); // already corrected for RC+STATUS
// }

// void close_toolLog(void)
// {

// }

errVal_t serializationFile::putData(void)
{
	return 0;
}

errVal_t serializationFile::getData(void)
{
	return 0;
}

void serializationFile::Close_File(void)
{
	return 0;
}

bool serializationFile::CheckFile(char* filespec)
{
	return true;
}

// void TpPdu::SetRCStatus(uint8_t rc, uint8_t status)
// {
//   int bcindex = (IsLongFrame()) ?
//       TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

//   pPDU[bcindex+1] = rc;
//   pPDU[bcindex+2] = status;
// }

int serializationFile::Open_File(char* filespec, int filespecLen)
{
	return 0;
}

serializationFile::serializationFile()
{
	pFD = NULL;
}

serializationFile::~serializationFile()
{
	if ( pFD )
	{
		// fclose(pFD);
		pFD = NULL;
	}
}

// void TpPdu::printMsg()
// {
	
// }

errVal_t NativeApp::initHostNameDns()
{
	return 0;
}

// string make_mq_name(const char *basename, char *instance )
// {
//   string u = "_";
//   string s = basename + u + instance;
//   return s;
// }

// errVal_t open_mqueue(mqd_t *p_mqDesc, char *mqName, int32_t qFlag,
//                      int32_t msgsize, int32_t maxmsg)
// {
// 	if (qFlag){
// 		struct mq_attr attr;

// 		attr.mq_flags = 0;
// 		attr.mq_msgsize = msgsize;
// 		attr.mq_maxmsg  = maxmsg;
// 		attr.mq_curmsgs = 0;

// 		*p_mqDesc = mq_open(mqName, qFlag, QMODE_PERMISSION, &attr);
// 	} else {
// 		*p_mqDesc = mq_open(mqName, qFlag);
// 	}
 
// 	/* Save mqueue info in the array */
// 	// hsrvrQueues[numQueues].mqDesc = *p_mqDesc;
// 	// hsrvrQueues[numQueues].qName  = mqName;
// 	// numQueues++;

// 	return 0;
// }

// void close_mqueues(void)
// {

// }

// void open_appcom(bool isServer, char *instance)
// {

// }

// uint8_t TpPdu::PduLength()
// {
// 	int bcindex = (IsLongFrame()) ? TP_OFFSET_BCOUNT_UNIQ : TP_OFFSET_BCOUNT_POLL;

// 	//  delim     1 or 5 addr    cm  BC  DATA        CHK
// 	//  xx		xxxxxxxxxx     xx  xx  xxxxxxxxxx  xx

// 	int bc = pPDU[bcindex];
// 	int len = bcindex + 1 + bc + 1;// + (index to counting number) + checksum
// 	// if the byte count doesn't already include the RC & DevStatus then somebody screwed up!
// 	// Don't add it here when you have nothing to put in it.                stevev 28mar2019
// 	//if (false == IsSTX())
// 	//{
// 	//	len += 2;   // +2 for RC+STATUS
// 	//}

// 	return len;
// }

// bool TpPdu::Validate(uint8_t requestBC)
// {
// 	if (RequestByteCount() < requestBC)
// 	{
// 	ProcessErrResponse(RC_TOO_FEW);
// 	return false;
// 	}

// 	// adjust BC downwards for extra data bytes
// 	if (RequestByteCount() > requestBC)
// 	{
// 	uint8_t deltabc = RequestByteCount() - requestBC; // too large by this much
// 	SetByteCount(ByteCount() - deltabc);  // accommodate cases with excessive byte count
// 	}

// 	return true;
// }

// void TpPdu::ProcessOkResponse(uint8_t rc, uint8_t bc)
// {
// 	// *this is the request PDU augmented with response data

// 	/* Build Response PDU in temp buffer, then copy to pPDU */
// 	uint8_t  rspBuff[TPPDU_MAX_FRAMELEN];
// 	memset_s(rspBuff, TPPDU_MAX_FRAMELEN, 0);

// 	/* Set response bytes starting with the Delimiter */
// 	uint16_t index = TP_OFFSET_DELIM;                   // Byte 0 of TP PDU

// 	uint8_t highbit = pPDU[index] & TPDELIM_ADDR_UNIQ;   // get high bit of request delimiter (& 0x80)
// 	//  rspBuff[index] = highbit | TPDELIM_FRAME_ACK;       // reply correctly for short and long frame

// 	if (highbit)
// 		rspBuff[index] = TPDELIM_ACK_UNIQ;  // 86
// 	else
// 		rspBuff[index] = TPDELIM_FRAME_ACK; // 06

// 	/* Set Long or Short Frame Address */
// 	uint8_t addrLen = highbit ? TPHDR_ADDRLEN_UNIQ : TPHDR_ADDRLEN_POLL;
// 	index += TPHDR_DELIMLEN;
// 	memcpy_s(&rspBuff[index], addrLen, &pPDU[index], addrLen);

// 	/* Apply bit masks for Master Address and Burst Mode (sometimes,
// 	* the Master may have these bits set wrong). Only Primary Master
// 	* expected.
// 	*/
// 	rspBuff[index]  = rspBuff[index] | TPPOLL_PRIM_MASTER_MASK;
// 	rspBuff[index] &= (~TPPOLL_FDEV_BURST_MASK);

// 	/* Set Command Number */
// 	index += addrLen;
// 	rspBuff[index] = pPDU[index];

// 	/* Set Byte Count */
// 	uint8_t rspLen = ByteCount() + addedByteCount;

// 	/* Add 1 byte each for RC and Device Status */
// 	rspLen += 2;

// 	//rspLen = bc < rspLen ? bc : rspLen; // BC can't exceed what device knows about
// 	rspLen = bc;

// 	index += TPHDR_CMDLEN;
// 	rspBuff[index] = rspLen;

// 	/* Set RC and Status Bytes */
// 	index += TPHDR_BCOUNTLEN;
// 	rspBuff[index++] = rc;
// 	rspBuff[index++] = STATUS_OK;

// 	// copy all data bytes, including exp cmd #
// 	memcpy_s(&rspBuff[index], TPPDU_MAX_DATALEN, DataBytes(), rspLen);

// 	index += rspLen;
// 	rspBuff[index++] = CheckSum(rspBuff, index);

// 	// save completed response PDU
// 	memcpy_s(pPDU, TPPDU_MAX_FRAMELEN, rspBuff, index);
// }

void bcm2835_delay(unsigned int millis)
{

}

errVal_t create_hs_semaphores(uint8_t createFlag)
{
	errVal_t errVal = SEM_ERROR;

	const char *funcName = "create_hs_semaphores";

	/* Create/open all synchronization semaphores */
	uint8_t initVal = (createFlag ? SEMTAKEN : SEMIGN);

	do
	{
		if (create_semaphores(createFlag) != NO_ERROR)
		{
			break;
		}
		// #191
		char semStop[SEM_NAME_SIZE] = "semStopMainThr";
		char semServ[SEM_NAME_SIZE] = "semServerTables";
		createUniqueName(semStop);

		p_semStopMainThr = open_a_semaphore(semStop, createFlag,
				initVal);
		if (p_semStopMainThr == NULL)
		{
			printf("Null p_semStopMainThr\n");
			break;
		}

		createUniqueName(semServ);
		p_semServerTables = open_a_semaphore(semServ, createFlag,
				initVal);
		if (p_semServerTables == NULL)
		{
			printf("Null p_semServerTables\n");
			break;
		}

		errVal = NO_ERROR;
	} while (FALSE);

	if ((createFlag) && (errVal == NO_ERROR))
	{
		// dbgp_init("  %d %s Semaphores Created\n", get_sem_count(), TOOL_NAME);
		sem_post(p_semServerTables);	// access to Server Tables is enabled
	}
	else
	{
		// fprintf(p_hsLogPtr, "  Failed to Create %s Semaphores\n",
		// TOOL_NAME);
	}
	dbgp_init("----------------------------------\n");

	return errVal;
}

static errVal_t create_hs_threads(void)
{
	const char *popRxThrName = "popRxMsg Thread";
	const char *popTxThrName = "popTxMsg Thread";
	const char *socketThrName = "Socket Thread";
	errVal_t errval = NO_ERROR;

	/* Thread to process HServer socket communication */
	errval = start_a_thread(&socketThrID, socketThrFunc, socketThrName);

	/* Thread for Server to receive msg from APP */
	errval = start_a_thread(&popRxThrID, popRxThrFunc, popRxThrName);

	/* Thread to run APP program */
	// if (eAppLaunch == LNCH_AUTO)
	// {
	// 	usleep(1000); // wait 1ms to allow other threads to spin up
	// 	errval = start_a_thread(&appThrID, appThrFunc, appThrName);
	// 	if (errval != NO_ERROR)
	// 	{
	// 		fprintf(p_hsLogPtr, "Error Creating %s\n", appThrName);
	// 		break;
	// 	}
	// 	hsThrCounter++;
	// 	dbgp_thr("   Created (#%d) %s\n", hsThrCounter, appThrName);
	// }

	return (errval);
}

void shutdown_server(void)
{
	// Send the signal for Ctrl+C to the thread.
	// #6004
	// sighandler_hs_endall(SIGINT);
}

void *run_io(void *data)
{
	while (1){
		printf("run_io running\n");
		k_sleep(K_MSEC(1000));
	}

	return NULL;
}

int main(void)
{
	int ret;
	errVal_t errval = NO_ERROR;

	// NativeApp app("ZephyrHART", "0.0");
	// pGlobalApp = &app;

	// AppConnector<AppPdu> globalAppConnector; // ctor sets config, incl address
	// pAppConnector = &globalAppConnector;

	// errval = app.commandline(0, NULL);
	// printf("commandline ret %d\n", errval);

	// clear_attached_devices();
	// ret = create_hs_semaphores(1);
	// printf("create_hs_semaphores ret %d\n", ret);

	// while(1){
	// 	k_sleep(K_MSEC(10));
	// }

	// ret = create_socket();

	// ret = initialize_hs_signals();
	// printf("initialize_hs_signals() ret %d\n", ret);
	// ret = do_hs_setup();
	// printf("create_socket() ret %d\n", ret);

	ret = create_mqueues(0);
	printf("create_mqueues() ret %d\n", ret);

	ret = create_hs_threads();
	printf("create_hs_threads() ret %d\n", ret);

	NativeApp app("ZephyrHART", "0.0");
	pGlobalApp = &app;

	AppConnector<AppPdu> globalAppConnector; // ctor sets config, incl address
	pAppConnector = &globalAppConnector;

	errval = app.commandline(0, NULL);
	printf("commandline ret %d\n", errval);

	errval = app.configure();
	printf("configure ret %d\n", errval);

	errval = app.initialize();
	printf("initialize ret %d\n", errval);

	printf("hello from %s!\n", app.GetName());
	pAppConnector->run(&app); // ends on abortApp

	while(1){
		k_sleep(K_MSEC(10));
	}

	return 0;
}