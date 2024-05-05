/*
 * Gated Release 4.x, 5.x, 6.x, 7.x
 * 
 * $Id: ospf_mib.c,v 1.16 2000/02/18 01:49:44 naamato Exp $
 */

/*
 * GateD Releases Unicast, Multicast, IPv6, RSd
 * 
 * Copyright (c) 1996,1997,1998,1999 
 * The Regents of the University of Michigan.
 * All Rights Reserved.
 * 
 * License to use, copy, modify, and distribute this software and its
 * documentation can be obtained from Merit Network, Inc. at the 
 * University of Michigan.
 * 
 * Merit GateD Consortium
 * Merit Network, Inc.
 * 4251 Plymouth Road, Suite C
 * Ann Arbor, MI 48105
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE REGENTS OF THE
 * UNIVERSITY OF MICHIGAN AND MERIT DO NOT WARRANT THAT THE FUNCTIONS 
 * CONTAINED IN THE SOFTWARE WILL MEET LICENSEE'S REQUIREMENTS OR THAT 
 * OPERATION WILL BE UNINTERRUPTED OR ERROR FREE. The Regents of the
 * University of Michigan and Merit shall not be liable for any special, 
 * indirect, incidental or consequential damages with respect to any claim 
 * by Licensee or any third party arising from use of the software. 
 * GateD was originated and developed through release 3.0 by Cornell 
 * University and its collaborators.
 * 
 * Please send questions or comments to gated-people@gated.org.
 *
 * Please submit bugs, bug fixes, and enhancements using the send-pr(1) 
 * utility or via the web at 
 * www.gated.org/gated-web/support/html/report_prob.html.
 * 
 * ------------------------------------------------------------------------
 *
 *      Copyright (c) 1990,1991,1992,1993,1994,1995 by Cornell University.
 *          All rights reserved.
 *
 *      THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY
 *      EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 *      LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *      AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *      GateD is based on Kirton's EGP, UC Berkeley's routing
 *      daemon   (routed), and DCN's HELLO routing Protocol.
 *      Development of GateD has been supported in part by the
 *      National Science Foundation.
 *
 * ------------------------------------------------------------------------
 *
 *      Portions of this software may fall under the following
 *      copyrights:
 *
 *      Copyright (c) 1988 Regents of the University of California.
 *      All rights reserved.
 *
 *      Redistribution and use in source and binary forms are
 *      permitted provided that the above copyright notice and
 *      this paragraph are duplicated in all such forms and that
 *      any documentation, advertising materials, and other
 *      materials related to such distribution and use
 *      acknowledge that the software was developed by the
 *      University of California, Berkeley.  The name of the
 *      University may not be used to endorse or promote
 *      products derived from this software without specific
 *      prior written permission.  THIS SOFTWARE IS PROVIDED
 *      ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES,
 *      INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 *      MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * __END_OF_COPYRIGHT__
 */

#define	INCLUDE_CMU_SNMP
#include "include.h"

#if	defined(PROTO_OSPF) && defined(PROTO_SNMP)
#include "inet/inet.h"
#include "ospf.h"

#if defined(PROTO_CMU_SNMP)
#include "snmp_cmu/snmp_cmu.h"
#elif defined(PROTO_SMUX)
#include "smux/smux_snmp.h"
#endif

#define	MIB_ME_INTRA	0x01
#define	MIB_ME_INTER	0x02
#define	MIB_ME_EXTERN	0x04
    
#define	MIB_NOAREASSUMMARY	1
#define	MIB_SENDAREASUMMARY	2

#define	MIB_OSPFMETRIC		1
#define	MIB_COMPARABLECOST	2
#define	MIB_NONCOMPARABLE	3

#define	MIB_ADVERTISE_MATCHING		1
#define	MIB_DONOT_ADVERTISE_MATCHING	2

    
#define	I_STATE_DOWN		1
#define	I_STATE_LOOPBACK	2
#define	I_STATE_WAITING		3
#define	I_STATE_P2P		4
#define	I_STATE_DR		5
#define	I_STATE_BDR		6
#define	I_STATE_DROTHER		7

#define	MIB_BLOCKED	1
#define	MIB_MULTICAST	2
#define	MIB_UNICAST	3

#define	MIB_BIT_TOS	0x01
#define	MIB_BIT_ASE	0x02
#define	MIB_BIT_MULTI	0x04
#define	MIB_BIT_NSSA	0x08

#define	N_STATE_DOWN		1
#define	N_STATE_ATTEMPT		2
#define	N_STATE_INIT		3
#define	N_STATE_2WAY		4
#define	N_STATE_EXSTART		5
#define	N_STATE_EXCHANGE	6
#define	N_STATE_LOADING		7
#define	N_STATE_FULL		8

#define	N_PERMANENCE_DYNAMIC	1
#define	N_PERMANENCE_PERMANENT	2

#define	MIB_AGGR_SUMMARYLINK		3
#define	MIB_AGGR_NSSAEXTERNALLINK	7

#define	MIB_ENABLED	1
#define	MIB_DISABLED	2

#define	MIB_TRUE	1
#define	MIB_FALSE	2

#define	MIB_VALID	1
#define	MIB_INVALID	2

/*
 * MIB compilation for ospf (oid 1.3.6.1.2.1.14)
 * compiled via mibcomp.pl (Revision: 1.2)
 * on Thu May 16 13:18:36 EDT 1996 on wolfe.bbn.com
 */


static u_char *var_ospfGeneralGroup();
static u_char *var_ospfAreaTable();
static u_char *var_ospfStubAreaTable();
static u_char *var_ospfLsdbTable();
static u_char *var_ospfAreaRangeTable();
static u_char *var_ospfHostTable();
static u_char *var_ospfIfTable();
static u_char *var_ospfIfMetricTable();
static u_char *var_ospfVirtIfTable();
static u_char *var_ospfNbrTable();
static u_char *var_ospfVirtNbrTable();
static u_char *var_ospfExtLsdbTable();
static u_char *var_ospfAreaAggregateTable();

/* Magic number defines for ospfGeneralGroup */
#define OSPFROUTERID                            	1
#define OSPFADMINSTAT                           	2
#define OSPFVERSIONNUMBER                       	3
#define OSPFAREABDRRTRSTATUS                    	4
#define OSPFASBDRRTRSTATUS                      	5
#define OSPFEXTERNLSACOUNT                      	6
#define OSPFEXTERNLSACKSUMSUM                   	7
#define OSPFTOSSUPPORT                          	8
#define OSPFORIGINATENEWLSAS                    	9
#define OSPFRXNEWLSAS                           	10
#define OSPFEXTLSDBLIMIT                        	11
#define OSPFMULTICASTEXTENSIONS                 	12

/* Magic number defines for ospfAreaTable */
#define OSPFAREAID                              	1
#define OSPFAUTHTYPE                            	2
#define OSPFIMPORTASEXTERN                      	3
#define OSPFSPFRUNS                             	4
#define OSPFAREABDRRTRCOUNT                     	5
#define OSPFASBDRRTRCOUNT                       	6
#define OSPFAREALSACOUNT                        	7
#define OSPFAREALSACKSUMSUM                     	8
#define OSPFAREASUMMARY                         	9
#define OSPFAREASTATUS                          	10

/* Magic number defines for ospfStubAreaTable */
#define OSPFSTUBAREAID                          	1
#define OSPFSTUBTOS                             	2
#define OSPFSTUBMETRIC                          	3
#define OSPFSTUBSTATUS                          	4
#define OSPFSTUBMETRICTYPE                      	5

/* Magic number defines for ospfLsdbTable */
#define OSPFLSDBAREAID                          	1
#define OSPFLSDBTYPE                            	2
#define OSPFLSDBLSID                            	3
#define OSPFLSDBROUTERID                        	4
#define OSPFLSDBSEQUENCE                        	5
#define OSPFLSDBAGE                             	6
#define OSPFLSDBCHECKSUM                        	7
#define OSPFLSDBADVERTISEMENT                   	8

/* Magic number defines for ospfAreaRangeTable */
#define OSPFAREARANGEAREAID                     	1
#define OSPFAREARANGENET                        	2
#define OSPFAREARANGEMASK                       	3
#define OSPFAREARANGESTATUS                     	4
#define OSPFAREARANGEEFFECT                     	5

/* Magic number defines for ospfHostTable */
#define OSPFHOSTIPADDRESS                       	1
#define OSPFHOSTTOS                             	2
#define OSPFHOSTMETRIC                          	3
#define OSPFHOSTSTATUS                          	4
#define OSPFHOSTAREAID                          	5

/* Magic number defines for ospfIfTable */
#define OSPFIFIPADDRESS                         	1
#define OSPFADDRESSLESSIF                       	2
#define OSPFIFAREAID                            	3
#define OSPFIFTYPE                              	4
#define OSPFIFADMINSTAT                         	5
#define OSPFIFRTRPRIORITY                       	6
#define OSPFIFTRANSITDELAY                      	7
#define OSPFIFRETRANSINTERVAL                   	8
#define OSPFIFHELLOINTERVAL                     	9
#define OSPFIFRTRDEADINTERVAL                   	10
#define OSPFIFPOLLINTERVAL                      	11
#define OSPFIFSTATE                             	12
#define OSPFIFDESIGNATEDROUTER                  	13
#define OSPFIFBACKUPDESIGNATEDROUTER            	14
#define OSPFIFEVENTS                            	15
#define OSPFIFAUTHKEY                           	16
#define OSPFIFSTATUS                            	17
#define OSPFIFMULTICASTFORWARDING               	18

/* Magic number defines for ospfIfMetricTable */
#define OSPFIFMETRICIPADDRESS                   	1
#define OSPFIFMETRICADDRESSLESSIF               	2
#define OSPFIFMETRICTOS                         	3
#define OSPFIFMETRICVALUE                       	4
#define OSPFIFMETRICSTATUS                      	5

/* Magic number defines for ospfVirtIfTable */
#define OSPFVIRTIFAREAID                        	1
#define OSPFVIRTIFNEIGHBOR                      	2
#define OSPFVIRTIFTRANSITDELAY                  	3
#define OSPFVIRTIFRETRANSINTERVAL               	4
#define OSPFVIRTIFHELLOINTERVAL                 	5
#define OSPFVIRTIFRTRDEADINTERVAL               	6
#define OSPFVIRTIFSTATE                         	7
#define OSPFVIRTIFEVENTS                        	8
#define OSPFVIRTIFAUTHKEY                       	9
#define OSPFVIRTIFSTATUS                        	10

/* Magic number defines for ospfNbrTable */
#define OSPFNBRIPADDR                           	1
#define OSPFNBRADDRESSLESSINDEX                 	2
#define OSPFNBRRTRID                            	3
#define OSPFNBROPTIONS                          	4
#define OSPFNBRPRIORITY                         	5
#define OSPFNBRSTATE                            	6
#define OSPFNBREVENTS                           	7
#define OSPFNBRLSRETRANSQLEN                    	8
#define OSPFNBMANBRSTATUS                       	9
#define OSPFNBMANBRPERMANENCE                   	10

/* Magic number defines for ospfVirtNbrTable */
#define OSPFVIRTNBRAREA                         	1
#define OSPFVIRTNBRRTRID                        	2
#define OSPFVIRTNBRIPADDR                       	3
#define OSPFVIRTNBROPTIONS                      	4
#define OSPFVIRTNBRSTATE                        	5
#define OSPFVIRTNBREVENTS                       	6
#define OSPFVIRTNBRLSRETRANSQLEN                	7

/* Magic number defines for ospfExtLsdbTable */
#define OSPFEXTLSDBTYPE                         	1
#define OSPFEXTLSDBLSID                         	2
#define OSPFEXTLSDBROUTERID                     	3
#define OSPFEXTLSDBSEQUENCE                     	4
#define OSPFEXTLSDBAGE                          	5
#define OSPFEXTLSDBCHECKSUM                     	6
#define OSPFEXTLSDBADVERTISEMENT                	7

/* Magic number defines for ospfAreaAggregateTable */
#define OSPFAREAAGGREGATEAREAID                 	1
#define OSPFAREAAGGREGATELSDBTYPE               	2
#define OSPFAREAAGGREGATENET                    	3
#define OSPFAREAAGGREGATEMASK                   	4
#define OSPFAREAAGGREGATESTATUS                 	5
#define OSPFAREAAGGREGATEEFFECT                 	6


static struct variable ospfGeneralGroup_variables[] = {
    {OSPFROUTERID, IPADDRESS, RWRITE, var_ospfGeneralGroup, 1, {1}},
    {OSPFADMINSTAT, INTEGER, RWRITE, var_ospfGeneralGroup, 1, {2}},
    {OSPFVERSIONNUMBER, INTEGER, RONLY, var_ospfGeneralGroup, 1, {3}},
    {OSPFAREABDRRTRSTATUS, INTEGER, RONLY, var_ospfGeneralGroup, 1, {4}},
    {OSPFASBDRRTRSTATUS, INTEGER, RWRITE, var_ospfGeneralGroup, 1, {5}},
    {OSPFEXTERNLSACOUNT, GAUGE, RONLY, var_ospfGeneralGroup, 1, {6}},
    {OSPFEXTERNLSACKSUMSUM, INTEGER, RONLY, var_ospfGeneralGroup, 1, {7}},
    {OSPFTOSSUPPORT, INTEGER, RWRITE, var_ospfGeneralGroup, 1, {8}},
    {OSPFORIGINATENEWLSAS, COUNTER, RONLY, var_ospfGeneralGroup, 1, {9}},
    {OSPFRXNEWLSAS, COUNTER, RONLY, var_ospfGeneralGroup, 1, {10}},
    {OSPFEXTLSDBLIMIT, INTEGER, RWRITE, var_ospfGeneralGroup, 1, {11}},
    {OSPFMULTICASTEXTENSIONS, INTEGER, RWRITE, var_ospfGeneralGroup, 1, {12}},
};

static struct variable ospfAreaTable_variables[] = {
    {OSPFAREAID, IPADDRESS, RONLY, var_ospfAreaTable, 2, {1, 1}},
    {OSPFAUTHTYPE, INTEGER, RWRITE, var_ospfAreaTable, 2, {1, 2}},
    {OSPFIMPORTASEXTERN, INTEGER, RWRITE, var_ospfAreaTable, 2, {1, 3}},
    {OSPFSPFRUNS, COUNTER, RONLY, var_ospfAreaTable, 2, {1, 4}},
    {OSPFAREABDRRTRCOUNT, GAUGE, RONLY, var_ospfAreaTable, 2, {1, 5}},
    {OSPFASBDRRTRCOUNT, GAUGE, RONLY, var_ospfAreaTable, 2, {1, 6}},
    {OSPFAREALSACOUNT, GAUGE, RONLY, var_ospfAreaTable, 2, {1, 7}},
    {OSPFAREALSACKSUMSUM, INTEGER, RONLY, var_ospfAreaTable, 2, {1, 8}},
    {OSPFAREASUMMARY, INTEGER, RWRITE, var_ospfAreaTable, 2, {1, 9}},
    {OSPFAREASTATUS, INTEGER, RWRITE, var_ospfAreaTable, 2, {1, 10}},
};

static struct variable ospfStubAreaTable_variables[] = {
    {OSPFSTUBAREAID, IPADDRESS, RONLY, var_ospfStubAreaTable, 2, {1, 1}},
    {OSPFSTUBTOS, INTEGER, RONLY, var_ospfStubAreaTable, 2, {1, 2}},
    {OSPFSTUBMETRIC, INTEGER, RWRITE, var_ospfStubAreaTable, 2, {1, 3}},
    {OSPFSTUBSTATUS, INTEGER, RWRITE, var_ospfStubAreaTable, 2, {1, 4}},
    {OSPFSTUBMETRICTYPE, INTEGER, RWRITE, var_ospfStubAreaTable, 2, {1, 5}},
};

static struct variable ospfLsdbTable_variables[] = {
    {OSPFLSDBAREAID, IPADDRESS, RONLY, var_ospfLsdbTable, 2, {1, 1}},
    {OSPFLSDBTYPE, INTEGER, RONLY, var_ospfLsdbTable, 2, {1, 2}},
    {OSPFLSDBLSID, IPADDRESS, RONLY, var_ospfLsdbTable, 2, {1, 3}},
    {OSPFLSDBROUTERID, IPADDRESS, RONLY, var_ospfLsdbTable, 2, {1, 4}},
    {OSPFLSDBSEQUENCE, INTEGER, RONLY, var_ospfLsdbTable, 2, {1, 5}},
    {OSPFLSDBAGE, INTEGER, RONLY, var_ospfLsdbTable, 2, {1, 6}},
    {OSPFLSDBCHECKSUM, INTEGER, RONLY, var_ospfLsdbTable, 2, {1, 7}},
    {OSPFLSDBADVERTISEMENT, STRING, RONLY, var_ospfLsdbTable, 2, {1, 8}},
};

static struct variable ospfAreaRangeTable_variables[] = {
    {OSPFAREARANGEAREAID, IPADDRESS, RONLY, var_ospfAreaRangeTable, 2, {1, 1}},
    {OSPFAREARANGENET, IPADDRESS, RONLY, var_ospfAreaRangeTable, 2, {1, 2}},
    {OSPFAREARANGEMASK, IPADDRESS, RWRITE, var_ospfAreaRangeTable, 2, {1, 3}},
    {OSPFAREARANGESTATUS, INTEGER, RWRITE, var_ospfAreaRangeTable, 2, {1, 4}},
    {OSPFAREARANGEEFFECT, INTEGER, RWRITE, var_ospfAreaRangeTable, 2, {1, 5}},
};

static struct variable ospfHostTable_variables[] = {
    {OSPFHOSTIPADDRESS, IPADDRESS, RONLY, var_ospfHostTable, 2, {1, 1}},
    {OSPFHOSTTOS, INTEGER, RONLY, var_ospfHostTable, 2, {1, 2}},
    {OSPFHOSTMETRIC, INTEGER, RWRITE, var_ospfHostTable, 2, {1, 3}},
    {OSPFHOSTSTATUS, INTEGER, RWRITE, var_ospfHostTable, 2, {1, 4}},
    {OSPFHOSTAREAID, IPADDRESS, RONLY, var_ospfHostTable, 2, {1, 5}},
};

static struct variable ospfIfTable_variables[] = {
    {OSPFIFIPADDRESS, IPADDRESS, RONLY, var_ospfIfTable, 2, {1, 1}},
    {OSPFADDRESSLESSIF, INTEGER, RONLY, var_ospfIfTable, 2, {1, 2}},
    {OSPFIFAREAID, IPADDRESS, RWRITE, var_ospfIfTable, 2, {1, 3}},
    {OSPFIFTYPE, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 4}},
    {OSPFIFADMINSTAT, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 5}},
    {OSPFIFRTRPRIORITY, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 6}},
    {OSPFIFTRANSITDELAY, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 7}},
    {OSPFIFRETRANSINTERVAL, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 8}},
    {OSPFIFHELLOINTERVAL, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 9}},
    {OSPFIFRTRDEADINTERVAL, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 10}},
    {OSPFIFPOLLINTERVAL, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 11}},
    {OSPFIFSTATE, INTEGER, RONLY, var_ospfIfTable, 2, {1, 12}},
    {OSPFIFDESIGNATEDROUTER, IPADDRESS, RONLY, var_ospfIfTable, 2, {1, 13}},
    {OSPFIFBACKUPDESIGNATEDROUTER, IPADDRESS, RONLY, var_ospfIfTable, 2, {1, 14}},
    {OSPFIFEVENTS, COUNTER, RONLY, var_ospfIfTable, 2, {1, 15}},
    {OSPFIFAUTHKEY, STRING, RWRITE, var_ospfIfTable, 2, {1, 16}},
    {OSPFIFSTATUS, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 17}},
    {OSPFIFMULTICASTFORWARDING, INTEGER, RWRITE, var_ospfIfTable, 2, {1, 18}},
};

static struct variable ospfIfMetricTable_variables[] = {
    {OSPFIFMETRICIPADDRESS, IPADDRESS, RONLY, var_ospfIfMetricTable, 2, {1, 1}},
    {OSPFIFMETRICADDRESSLESSIF, INTEGER, RONLY, var_ospfIfMetricTable, 2, {1, 2}},
    {OSPFIFMETRICTOS, INTEGER, RONLY, var_ospfIfMetricTable, 2, {1, 3}},
    {OSPFIFMETRICVALUE, INTEGER, RWRITE, var_ospfIfMetricTable, 2, {1, 4}},
    {OSPFIFMETRICSTATUS, INTEGER, RWRITE, var_ospfIfMetricTable, 2, {1, 5}},
};

static struct variable ospfVirtIfTable_variables[] = {
    {OSPFVIRTIFAREAID, IPADDRESS, RONLY, var_ospfVirtIfTable, 2, {1, 1}},
    {OSPFVIRTIFNEIGHBOR, IPADDRESS, RONLY, var_ospfVirtIfTable, 2, {1, 2}},
    {OSPFVIRTIFTRANSITDELAY, INTEGER, RWRITE, var_ospfVirtIfTable, 2, {1, 3}},
    {OSPFVIRTIFRETRANSINTERVAL, INTEGER, RWRITE, var_ospfVirtIfTable, 2, {1, 4}},
    {OSPFVIRTIFHELLOINTERVAL, INTEGER, RWRITE, var_ospfVirtIfTable, 2, {1, 5}},
    {OSPFVIRTIFRTRDEADINTERVAL, INTEGER, RWRITE, var_ospfVirtIfTable, 2, {1, 6}},
    {OSPFVIRTIFSTATE, INTEGER, RONLY, var_ospfVirtIfTable, 2, {1, 7}},
    {OSPFVIRTIFEVENTS, COUNTER, RONLY, var_ospfVirtIfTable, 2, {1, 8}},
    {OSPFVIRTIFAUTHKEY, STRING, RWRITE, var_ospfVirtIfTable, 2, {1, 9}},
    {OSPFVIRTIFSTATUS, INTEGER, RWRITE, var_ospfVirtIfTable, 2, {1, 10}},
};

static struct variable ospfNbrTable_variables[] = {
    {OSPFNBRIPADDR, IPADDRESS, RONLY, var_ospfNbrTable, 2, {1, 1}},
    {OSPFNBRADDRESSLESSINDEX, INTEGER, RONLY, var_ospfNbrTable, 2, {1, 2}},
    {OSPFNBRRTRID, IPADDRESS, RONLY, var_ospfNbrTable, 2, {1, 3}},
    {OSPFNBROPTIONS, INTEGER, RONLY, var_ospfNbrTable, 2, {1, 4}},
    {OSPFNBRPRIORITY, INTEGER, RWRITE, var_ospfNbrTable, 2, {1, 5}},
    {OSPFNBRSTATE, INTEGER, RONLY, var_ospfNbrTable, 2, {1, 6}},
    {OSPFNBREVENTS, COUNTER, RONLY, var_ospfNbrTable, 2, {1, 7}},
    {OSPFNBRLSRETRANSQLEN, GAUGE, RONLY, var_ospfNbrTable, 2, {1, 8}},
    {OSPFNBMANBRSTATUS, INTEGER, RWRITE, var_ospfNbrTable, 2, {1, 9}},
    {OSPFNBMANBRPERMANENCE, INTEGER, RWRITE, var_ospfNbrTable, 2, {1, 10}},
};

static struct variable ospfVirtNbrTable_variables[] = {
    {OSPFVIRTNBRAREA, IPADDRESS, RONLY, var_ospfVirtNbrTable, 2, {1, 1}},
    {OSPFVIRTNBRRTRID, IPADDRESS, RONLY, var_ospfVirtNbrTable, 2, {1, 2}},
    {OSPFVIRTNBRIPADDR, IPADDRESS, RONLY, var_ospfVirtNbrTable, 2, {1, 3}},
    {OSPFVIRTNBROPTIONS, INTEGER, RONLY, var_ospfVirtNbrTable, 2, {1, 4}},
    {OSPFVIRTNBRSTATE, INTEGER, RONLY, var_ospfVirtNbrTable, 2, {1, 5}},
    {OSPFVIRTNBREVENTS, COUNTER, RONLY, var_ospfVirtNbrTable, 2, {1, 6}},
    {OSPFVIRTNBRLSRETRANSQLEN, GAUGE, RONLY, var_ospfVirtNbrTable, 2, {1, 7}},
};

static struct variable ospfExtLsdbTable_variables[] = {
    {OSPFEXTLSDBTYPE, INTEGER, RONLY, var_ospfExtLsdbTable, 2, {1, 1}},
    {OSPFEXTLSDBLSID, IPADDRESS, RONLY, var_ospfExtLsdbTable, 2, {1, 2}},
    {OSPFEXTLSDBROUTERID, IPADDRESS, RONLY, var_ospfExtLsdbTable, 2, {1, 3}},
    {OSPFEXTLSDBSEQUENCE, INTEGER, RONLY, var_ospfExtLsdbTable, 2, {1, 4}},
    {OSPFEXTLSDBAGE, INTEGER, RONLY, var_ospfExtLsdbTable, 2, {1, 5}},
    {OSPFEXTLSDBCHECKSUM, INTEGER, RONLY, var_ospfExtLsdbTable, 2, {1, 6}},
    {OSPFEXTLSDBADVERTISEMENT, STRING, RONLY, var_ospfExtLsdbTable, 2, {1, 7}},
};

static struct variable ospfAreaAggregateTable_variables[] = {
    {OSPFAREAAGGREGATEAREAID, IPADDRESS, RONLY, var_ospfAreaAggregateTable, 2, {1, 1}},
    {OSPFAREAAGGREGATELSDBTYPE, INTEGER, RONLY, var_ospfAreaAggregateTable, 2, {1, 2}},
    {OSPFAREAAGGREGATENET, IPADDRESS, RONLY, var_ospfAreaAggregateTable, 2, {1, 3}},
    {OSPFAREAAGGREGATEMASK, IPADDRESS, RWRITE, var_ospfAreaAggregateTable, 2, {1, 4}},
    {OSPFAREAAGGREGATESTATUS, INTEGER, RWRITE, var_ospfAreaAggregateTable, 2, {1, 5}},
    {OSPFAREAAGGREGATEEFFECT, INTEGER, RWRITE, var_ospfAreaAggregateTable, 2, {1, 6}},
};

static struct subtree ospf_subtrees[] = {
    {{MIB, 14, 1}, 8,
	(struct variable *)ospfGeneralGroup_variables,
	sizeof(ospfGeneralGroup_variables)/sizeof(*ospfGeneralGroup_variables),
	sizeof(*ospfGeneralGroup_variables)},
    {{MIB, 14, 2}, 8,
	(struct variable *)ospfAreaTable_variables,
	sizeof(ospfAreaTable_variables)/sizeof(*ospfAreaTable_variables),
	sizeof(*ospfAreaTable_variables)},
    {{MIB, 14, 3}, 8,
	(struct variable *)ospfStubAreaTable_variables,
      sizeof(ospfStubAreaTable_variables)/sizeof(*ospfStubAreaTable_variables),
	sizeof(*ospfStubAreaTable_variables)},
    {{MIB, 14, 4}, 8,
	(struct variable *)ospfLsdbTable_variables,
	sizeof(ospfLsdbTable_variables)/sizeof(*ospfLsdbTable_variables),
	sizeof(*ospfLsdbTable_variables)},
    {{MIB, 14, 5}, 8,
	(struct variable *)ospfAreaRangeTable_variables,
    sizeof(ospfAreaRangeTable_variables)/sizeof(*ospfAreaRangeTable_variables),
	sizeof(*ospfAreaRangeTable_variables)},
    {{MIB, 14, 6}, 8,
	(struct variable *)ospfHostTable_variables,
	sizeof(ospfHostTable_variables)/sizeof(*ospfHostTable_variables),
	sizeof(*ospfHostTable_variables)},
    {{MIB, 14, 7}, 8,
	(struct variable *)ospfIfTable_variables,
	sizeof(ospfIfTable_variables)/sizeof(*ospfIfTable_variables),
	sizeof(*ospfIfTable_variables)},
    {{MIB, 14, 8}, 8,
	(struct variable *)ospfIfMetricTable_variables,
      sizeof(ospfIfMetricTable_variables)/sizeof(*ospfIfMetricTable_variables),
	sizeof(*ospfIfMetricTable_variables)},
    {{MIB, 14, 9}, 8,
	(struct variable *)ospfVirtIfTable_variables,
	sizeof(ospfVirtIfTable_variables)/sizeof(*ospfVirtIfTable_variables),
	sizeof(*ospfVirtIfTable_variables)},
    {{MIB, 14, 10}, 8,
	(struct variable *)ospfNbrTable_variables,
	sizeof(ospfNbrTable_variables)/sizeof(*ospfNbrTable_variables),
	sizeof(*ospfNbrTable_variables)},
    {{MIB, 14, 11}, 8,
	(struct variable *)ospfVirtNbrTable_variables,
	sizeof(ospfVirtNbrTable_variables)/sizeof(*ospfVirtNbrTable_variables),
	sizeof(*ospfVirtNbrTable_variables)},
    {{MIB, 14, 12}, 8,
	(struct variable *)ospfExtLsdbTable_variables,
	sizeof(ospfExtLsdbTable_variables)/sizeof(*ospfExtLsdbTable_variables),
	sizeof(*ospfExtLsdbTable_variables)},
    {{MIB, 14, 14}, 8,
	(struct variable *)ospfAreaAggregateTable_variables,
	sizeof(ospfAreaAggregateTable_variables)/sizeof(*ospfAreaAggregateTable_variables),
	sizeof(*ospfAreaAggregateTable_variables)}
};

/*
 * var_ospfGeneralGroup: Callbacks for oid mib-2.ospf.1
 * Single-instanced
 */
static u_char *
var_ospfGeneralGroup(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
    if ( !single_inst_check(vp, name, length, exact) )
        return NULL;

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFROUTERID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(ospf.router_id ? ospf.router_id : inet_routerid);	

    case OSPFADMINSTAT:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(ospf.ospf_admin_stat == OSPF_ENABLED
			 ? MIB_ENABLED : MIB_DISABLED);

    case OSPFVERSIONNUMBER:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(OSPF_VERSION);

    case OSPFAREABDRRTRSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(IAmBorderRtr ? MIB_TRUE : MIB_FALSE);

    case OSPFASBDRRTRSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(ospf.asbr ? MIB_TRUE : MIB_FALSE);

    case OSPFEXTERNLSACOUNT:
	/* C type GAUGE, MIB type Gauge */
	return O_INTEGER(ospf.db_ase_cnt);

    case OSPFEXTERNLSACKSUMSUM:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(ospf.db_chksumsum);

    case OSPFTOSSUPPORT:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_FALSE);

    case OSPFORIGINATENEWLSAS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ospf.orig_new_lsa);

    case OSPFRXNEWLSAS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(ospf.rx_new_lsa);

    case OSPFEXTLSDBLIMIT:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(-1);	/* Not supported */

    case OSPFMULTICASTEXTENSIONS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(0);	/* Not supported */

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
}

/* Area group */


static struct AREA *
o_area_lookup (register unsigned int * ip, u_int len, int isnext)
{
    static unsigned int *last;
    static struct AREA *last_area;

    if (snmp_last_match(&last, ip, len, isnext)) {
	return last_area;
    }

    if (len) {
	u_int32 area_id;
	register struct AREA *area;
	
	oid2ipaddr(ip, &area_id, len);

	GNTOHL(area_id);

	AREA_LIST(area) {
	    register u_int32 cur_id = ntohl(area->area_id);
	    
	    if (cur_id == area_id) {
		if (!isnext || len < sizeof(struct in_addr)) {
		    return last_area = area;
		}
	    } else if (cur_id > area_id){
		return last_area = isnext ? area : (struct AREA *) 0;
	    }
	} AREA_LIST_END(area) ;

	return last_area = (struct AREA *) 0;
    }
    
    return last_area = ospf.area.area_forw;
}


/*
 * var_ospfAreaTable: Callbacks for oid mib-2.ospf.2
 */
static u_char *
var_ospfAreaTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
    /* INDEX { ospfAreaID } */
#define NDX_SIZE (int)(	(sizeof (area->area_id)))
    register struct AREA *area;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(area = o_area_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(area = o_area_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(area->area_id, vp->namelen, name);
	*length = vp->namelen + NDX_SIZE;
    }

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFAREAID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(area->area_id);

    case OSPFAUTHTYPE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(area->authtype);

    case OSPFIMPORTASEXTERN:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(BIT_TEST(area->area_flags, OSPF_AREAF_STUB)
			 ? MIB_FALSE : MIB_TRUE);

    case OSPFSPFRUNS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(area->spfcnt);

    case OSPFAREABDRRTRCOUNT:
	/* C type GAUGE, MIB type Gauge */
	return O_INTEGER(area->abr_cnt);

    case OSPFASBDRRTRCOUNT:
	/* C type GAUGE, MIB type Gauge */
	return O_INTEGER(area->asbr_cnt);

    case OSPFAREALSACOUNT:
	/* C type GAUGE, MIB type Gauge */
	return O_INTEGER(area->db_int_cnt);	

    case OSPFAREALSACKSUMSUM:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(area->db_chksumsum);

    case OSPFAREASUMMARY:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_SENDAREASUMMARY);

    case OSPFAREASTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_VALID);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}

/* Stub area group */

static struct AREA *
o_stub_lookup (register unsigned int * ip, u_int len, int isnext)
{
    u_int32 area_id = 0;
    register struct AREA *area;
    static unsigned int *last;
    static struct AREA *last_area;

    if (snmp_last_match(&last, ip, len, isnext)) {
	return last_area;
    }

    oid2ipaddr(ip, &area_id, len);
    GNTOHL(area_id);

    if (len > sizeof(struct in_addr) && ip[sizeof (struct in_addr)]) {
        /* We don't support TOS */
	return last_area = (struct AREA *) 0;
    }

    AREA_LIST(area) {
	register u_int32 cur_id;

	if (!BIT_TEST(area->area_flags, OSPF_AREAF_STUB)) {
	    /* Not a stub area */
	    continue;
	}

	cur_id = ntohl(area->area_id);

	if (cur_id == area_id) {
	    if (!isnext || len < sizeof(struct in_addr)) {
		return last_area = area;
	    }
	} else if (cur_id > area_id){
	    return last_area = isnext ? area : (struct AREA *) 0;
	}
    } AREA_LIST_END(area) ;

    return last_area = (struct AREA *) 0;
}


/*
 * var_ospfStubAreaTable: Callbacks for oid mib-2.ospf.3
 */
static u_char *
var_ospfStubAreaTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfStubAreaId, ospfStubTOS } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + 1))

    register struct AREA *area;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(area = o_stub_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(area = o_stub_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(area->area_id, vp->namelen, name);
	name[vp->namelen + 4] = 0; /* no TOS support */
	*length = vp->namelen + NDX_SIZE;
    }

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFSTUBAREAID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(area->area_id);

    case OSPFSTUBTOS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(0);

    case OSPFSTUBMETRIC:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(BIT_TEST(area->area_flags, OSPF_AREAF_STUB_DEFAULT)
			 ? area->dflt_metric : (unsigned) -1);

    case OSPFSTUBSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_VALID);

    case OSPFSTUBMETRICTYPE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_OSPFMETRIC);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}

/* Link state database group */

#define	MLSDB_LIST(list, lpp)		for ((lpp) = (list); *(lpp); (lpp)++)
#define	MLSDB_LIST_END(list, lpp)	

static int
o_lsdb_compare (const VOID_T le1, const VOID_T le2)
{
    register u_int32 key1_0 = ntohl(LS_ID(*((struct LSDB * const *) le1)));
    register u_int32 key1_1 = ntohl(ADV_RTR(*((struct LSDB * const *) le1)));
    register u_int32 key2_0 = ntohl(LS_ID(*((struct LSDB * const *) le2)));
    register u_int32 key2_1 = ntohl(ADV_RTR(*((struct LSDB * const *) le2)));

    if (key1_0 > key2_0) {
	return 1;
    } else if (key1_0 < key2_0
	       || key1_1 < key2_1) {
	return -1;
    } else if (key1_1 > key2_1) {
	return 1;
    }

    return 0;
}


static void
o_lsdb_get (u_int lsdb_cnt, struct LSDB_HEAD * list_head,
    struct LSDB *** list, u_int * size, u_int * cnt)
{
    register struct LSDB **lsdbp;
    register struct LSDB_HEAD *hp;

    if (*size < lsdb_cnt) {
	if (*list) {
	    lsdbp = *list;

	    task_block_reclaim((size_t) ((*size + 1) * sizeof (struct LSDB *)), (void_t) *list);
	}

	*size = lsdb_cnt;

	*list = (struct LSDB **) task_block_malloc((size_t) ((*size + 1) * sizeof (struct LSDB *)));
    }

    lsdbp = *list;
    *cnt = 0;
    
    LSDB_HEAD_LIST(list_head, hp, 0, HTBLSIZE) {
	register struct LSDB *db;

	LSDB_LIST(hp, db) {
	    if (!DB_FREEME(db)) {
		*lsdbp++ = db;
		(*cnt)++;		     
	    }
	} LSDB_LIST_END(hp, db) ;
    } LSDB_HEAD_LIST_END(list_head, hp, 0, HTBLSIZE) ;

    *lsdbp++ = (struct LSDB *) 0;

    qsort(*list,
	  *cnt,
	  sizeof (struct LSDB **),
	  o_lsdb_compare);
}


static struct LSDB *
o_lsdb_lookup (register unsigned int * ip, u_int len, int isnext)
{
    static struct LSDB *last_lsdb;
    static unsigned int *last;
    static int last_quantum;

    if (last_quantum != snmp_quantum) {
	int changed = 0;
	register struct AREA *area;

	last_quantum = snmp_quantum;

	AREA_LIST(area) {
	    if (area->db_chksumsum != area->mib_chksumsum) {
		u_int type;
		
		/* Time to rebuild the sorted lists */

		changed++;

		for (type = LS_RTR; type < LS_ASE; type++) {
		    o_lsdb_get(area->db_int_cnt,
			       area->htbl[type],
			       &area->mib_lsdb_list[type],
			       &area->mib_lsdb_size[type],
			       &area->mib_lsdb_cnt[type]);
		}

		area->mib_chksumsum = area->db_chksumsum;
	    }
	} AREA_LIST_END(area);

	if (changed && last) {
	    task_mem_free((task *) 0, (void_t) last);
	    last = (unsigned int *) 0;
	}
    }

    if (snmp_last_match(&last, ip, len, isnext)) {
	return last_lsdb;
    }

    if (len) {
	u_int32 area_id, key0, key1;
	int type_id = 0;
	register struct AREA *ap;

	oid2ipaddr(ip, &area_id, len);
	ip += sizeof (struct in_addr);
	GNTOHL(area_id);

        if (len > sizeof(struct in_addr))
	    type_id = *ip++;

	oid2ipaddr(ip, &key0, len - sizeof(struct in_addr) - 1);
	ip += sizeof (struct in_addr);
	GNTOHL(key0);

	oid2ipaddr(ip, &key1, len - 2 * sizeof(struct in_addr) - 1);
	GNTOHL(key1);

	if (isnext) {
	    register u_int next = 0;

	    AREA_LIST(ap) {
		register u_int type;

		if (!next && area_id > ntohl(ap->area_id)) {
		    continue;
		}
		
		for (type = type_id; type < LS_ASE; type++) {
		    register struct LSDB **lpp;

		    if (ap->mib_lsdb_list[type]) {
			MLSDB_LIST(ap->mib_lsdb_list[type], lpp) {
			    register struct LSDB *lp = *lpp;
			    register u_int32 cur_key0 = ntohl(LS_ID(lp));
			    register u_int32 cur_key1 = ntohl(ADV_RTR(lp));

			    if (next
				|| cur_key0 > key0
				|| (cur_key0 == key0
				    && (cur_key1 > key1 || 
              (cur_key1 == key1 && len < 2 * sizeof(struct in_addr) - 1)))) {
				return last_lsdb = lp;
			    }
			    if (cur_key0 == key0
				&& cur_key1 == key1) {
				next++;
			    }
			} MLSDB_LIST_END(ap->mib_lsdb_list[type], lpp) ;
		    }

		    next++;
		}
		type_id = LS_RTR;
	    } AREA_LIST_END(ap) ;
	} else {
	    AREA_LIST(ap) {
		register struct LSDB **lpp;
		register u_int32 cur_area_id = ntohl(ap->area_id);

		if (area_id > cur_area_id) {
		    continue;
		} else if (area_id < cur_area_id) {
		    break;
		}

		/* XXX - binary search */

		MLSDB_LIST(ap->mib_lsdb_list[type_id], lpp) {
		    register struct LSDB *lp = *lpp;
		    register u_int32 cur_key0 = ntohl(LS_ID(lp));
		    register u_int32 cur_key1 = ntohl(ADV_RTR(lp));

		    if (key0 > cur_key0) {
			continue;
		    } else if (key0 == cur_key0) {
			if (key1 > cur_key1) {
			    continue;
			} else if (key1 == cur_key1) {
			    return last_lsdb = lp;
			}
		    }
		    return last_lsdb = (struct LSDB *) 0;
		} MLSDB_LIST_END(ap->mib_lsdb_list[type], lpp);
	    } AREA_LIST_END(ap) ;
	}
    } else {
	register struct AREA *ap;

	/* Find first lsdb */

	AREA_LIST(ap) {
	    register u_int type;

	    for (type = LS_RTR; type < LS_ASE; type++) {
		register struct LSDB **list = (struct LSDB **) ap->mib_lsdb_list[type];

		if (*list) {
		    return last_lsdb = *list;
		}
	    }
	} AREA_LIST_END(ap) ;
    }
		
    return last_lsdb = (struct LSDB *) 0;
}

/*
 * var_ospfLsdbTable: Callbacks for oid mib-2.ospf.4
 */
static u_char *
var_ospfLsdbTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfLsdbAreaId, ospfLsdbType, ospfLsdbLsid, ospfLsdbRouterId } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + 1 + sizeof (struct in_addr) + sizeof (struct in_addr)))

    register struct LSDB *lsdb;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(lsdb = o_lsdb_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	    /*
	     * Zero non-set bytes in name
	     */
	    if (len < NDX_SIZE)
		bzero((void_t *)&name[*length], (NDX_SIZE - len) * sizeof(oid));
	}
	if (!(lsdb = o_lsdb_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(lsdb->lsdb_area->area_id, vp->namelen, name);
	name[vp->namelen + 4] = LS_TYPE(lsdb);
	put_ipaddr(LS_ID(lsdb), vp->namelen + 5, name);
	put_ipaddr(ADV_RTR(lsdb), vp->namelen + 9, name);
	*length = vp->namelen + NDX_SIZE;
    }


    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFLSDBAREAID:
	/* C type IPADDRESS, MIB type IpAddress */
				/* $$$?? */
	return O_IPADDR_RAW(lsdb->lsdb_area->area_id);

    case OSPFLSDBTYPE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(LS_TYPE(lsdb));

    case OSPFLSDBLSID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(LS_ID(lsdb));

    case OSPFLSDBROUTERID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(ADV_RTR(lsdb));

    case OSPFLSDBSEQUENCE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(LS_SEQ(lsdb));

    case OSPFLSDBAGE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIN(ADV_AGE(lsdb), MaxAge));

    case OSPFLSDBCHECKSUM:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(LS_CKS(lsdb));

    case OSPFLSDBADVERTISEMENT:
	/* C type STRING, MIB type OctetString */
	assert(ntohs(LS_LEN(lsdb)) < RETURN_BUF_SIZE);
	bcopy(DB_RTR(lsdb), return_buf, ntohs(LS_LEN(lsdb)));
	return return_buf;

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}
/**/

static struct LSDB *
o_ase_lookup (register unsigned int * ip, u_int len, int isnext)
{
    static struct LSDB *last_lsdb;
    static unsigned int *last;
    static int last_quantum;

    if (last_quantum != snmp_quantum) {

	last_quantum = snmp_quantum;

	if (ospf.db_chksumsum != ospf.mib_ase_chksumsum) {
	    o_lsdb_get(ospf.db_ase_cnt,
		       ospf.ase,
		       &ospf.mib_ase_list,
		       &ospf.mib_ase_size,
		       &ospf.mib_ase_cnt);

	    ospf.mib_ase_chksumsum = ospf.db_chksumsum;

	    if (last) {
		task_mem_free((task *) 0, (void_t) last);
		last = (unsigned int *) 0;
	    }
	}
    }

    if (snmp_last_match(&last, ip, len, isnext)) {
	return last_lsdb;
    }

    if (!ospf.mib_ase_cnt) {
	return last_lsdb = (struct LSDB *) 0;
    }
    
    if (len) {
	u_int type_id;
	u_int32 key0, key1;
	register struct LSDB **lpp;

	type_id = *ip++;
	if (type_id != LS_ASE) {
	    return last_lsdb = (struct LSDB *) 0;
	}
	oid2ipaddr(ip, &key0, len);
	GNTOHL(key0);
	ip += sizeof (struct in_addr);

	oid2ipaddr(ip, &key1, len);
	GNTOHL(key1);

	if (isnext) {
	    MLSDB_LIST(ospf.mib_ase_list, lpp) {
		register struct LSDB *lp = *lpp;
		register u_int32 cur_key0 = ntohl(LS_ID(lp));
		register u_int32 cur_key1 = ntohl(ADV_RTR(lp));

		if (cur_key0 > key0
		    || (cur_key0 == key0
			&& (cur_key1 > key1
                            || (cur_key1 == key1 
                                && len < 2 * sizeof(struct in_addr))))) {
		    return last_lsdb = lp;
		}
	    } MLSDB_LIST_END(ospf.mib_ase_list, lpp) ;
	} else {
	    /* XXX - binary search */

	    MLSDB_LIST(ospf.mib_ase_list, lpp) {
		register struct LSDB *lp = *lpp;
		register u_int32 cur_key0 = ntohl(LS_ID(lp));
		register u_int32 cur_key1 = ntohl(ADV_RTR(lp));

		if (key0 < cur_key0) {
		    continue;
		} else if (key0 == cur_key0) {
		    if (key1 < cur_key1) {
			continue;
		    } else if (key1 == cur_key1) {
			return last_lsdb = lp;
		    }
		}
		return last_lsdb = (struct LSDB *) 0;
	    } MLSDB_LIST_END(ospf.mib_ase_list, lpp);
	}
    } else {

	return last_lsdb = *ospf.mib_ase_list;
    }
		
    return last_lsdb = (struct LSDB *) 0;
}


/*
 * var_ospfExtLsdbTable: Callbacks for oid mib-2.ospf.12
 */
static u_char *
var_ospfExtLsdbTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfExtLsdbType, ospfExtLsdbLsid, ospfExtLsdbRouterId } */
/*=INDEX { int, ip, ip } */
#define NDX_SIZE (int)(	(1 + sizeof (struct in_addr) + sizeof (struct in_addr)))

    register struct LSDB *lsdb;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(lsdb = o_ase_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(lsdb = o_ase_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	name[vp->namelen] = LS_TYPE(lsdb);
	put_ipaddr(LS_ID(lsdb), vp->namelen + 1, name);
	put_ipaddr(ADV_RTR(lsdb), vp->namelen + 5, name);
	*length = vp->namelen + NDX_SIZE;
    }

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFEXTLSDBTYPE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(LS_TYPE(lsdb));

    case OSPFEXTLSDBLSID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(LS_ID(lsdb));

    case OSPFEXTLSDBROUTERID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(ADV_RTR(lsdb));

    case OSPFEXTLSDBSEQUENCE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(LS_SEQ(lsdb));

    case OSPFEXTLSDBAGE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIN(ADV_AGE(lsdb), MaxAge));

    case OSPFEXTLSDBCHECKSUM:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(LS_CKS(lsdb));

    case OSPFEXTLSDBADVERTISEMENT:
	/* C type STRING, MIB type OctetString */
	assert(ntohs(LS_LEN(lsdb)) < RETURN_BUF_SIZE);
	bcopy(DB_RTR(lsdb), return_buf, ntohs(LS_LEN(lsdb)));
	return return_buf;

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}

/**/

/* Network range group */
static struct NET_RANGE *
o_range_lookup (register unsigned int * ip, u_int len, int isnext, struct AREA ** return_area)
{
    int next = FALSE;
    u_int32 nr_net;
    u_int32 area_id;
    register struct AREA *area;
    register struct NET_RANGE *nr;
    static struct NET_RANGE *last_nr;
    static struct AREA *last_area;
    static unsigned int *last;

    if (snmp_last_match(&last, ip, len, isnext)) {
	*return_area = last_area;
	return last_nr;
    }

    oid2ipaddr(ip, &area_id, len);
    GNTOHL(area_id);

    ip += sizeof(struct in_addr);
    oid2ipaddr(ip, &nr_net, len - sizeof(struct in_addr));
    GNTOHL(nr_net);

    AREA_LIST(area) {
	register u_int32 cur_id = ntohl(area->area_id);
	
	if (cur_id < area_id) {
	    continue;
	}

	RANGE_LIST(nr, area) {
	    u_int32 cur_net = ntohl(nr->nr_net);

	    if (next) {
		goto got_it;
	    }

	    if (cur_net < nr_net)
		continue;
	    
	    if (cur_net == nr_net) {
		if (isnext && len >= 2 * sizeof(struct in_addr)) {
		    next = TRUE;
		} else {
		    goto got_it;
		}
	    } else if (cur_net > nr_net) {
		if (!isnext) {
		    nr = (struct NET_RANGE *) 0;
		}
		goto got_it;
	    }
	} RANGE_LIST_END(nr, area) ;
    } AREA_LIST_END(area) ;

    nr = (struct NET_RANGE *) 0;
    area = (struct AREA *) 0;

 got_it:
    *return_area = last_area = area;
    return last_nr = nr;
}


/*
 * var_ospfAreaRangeTable: Callbacks for oid mib-2.ospf.5
 */
static u_char *
var_ospfAreaRangeTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
    /* INDEX { ospfAreaRangeAreaId, ospfAreaRangeNet } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + sizeof (struct in_addr)))
    int len;
    struct AREA *area;
    struct NET_RANGE *range;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(range = o_range_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE,
				     &area)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(range = o_range_lookup((u_int *)&name[vp->namelen], len, TRUE, &area)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(area->area_id, vp->namelen, name);
	put_ipaddr(range->nr_net, vp->namelen + 4, name);
	*length = vp->namelen + NDX_SIZE;
    }

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFAREARANGEAREAID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(area->area_id);

    case OSPFAREARANGENET:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(range->nr_net);

    case OSPFAREARANGEMASK:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(range->nr_mask);

    case OSPFAREARANGESTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_VALID);

    case OSPFAREARANGEEFFECT:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER((range->nr_status == Advertise)
		   ? MIB_ADVERTISE_MATCHING : MIB_DONOT_ADVERTISE_MATCHING);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}

/**/

/* Network range group */
static struct NET_RANGE *
o_aggr_lookup (register unsigned int * ip, u_int len, int isnext, struct AREA ** return_area)
{
    int next = FALSE;
    u_int32 nr_net;
    u_int32 nr_mask;
    u_int32 area_id;
    register struct AREA *area;
    register struct NET_RANGE *nr;
    static struct NET_RANGE *last_nr;
    static struct AREA *last_area;
    static unsigned int *last;

    if (snmp_last_match(&last, ip, len, isnext)) {
	*return_area = last_area;
	return last_nr;
    }

    oid2ipaddr(ip, &area_id, len);
    GNTOHL(area_id);
    ip += sizeof (struct in_addr);

    if (len > sizeof(struct in_addr)) {
        if (*ip++ != MIB_AGGR_SUMMARYLINK) {
	    nr = (struct NET_RANGE *) 0;
	    area = (struct AREA *) 0;
	    goto got_it;
        }
    }

    oid2ipaddr(ip, &nr_net, len - sizeof(struct in_addr) - 1);
    GNTOHL(nr_net);
    ip += sizeof (struct in_addr);

    oid2ipaddr(ip, &nr_mask, len - 2 * sizeof(struct in_addr) - 1);
    GNTOHL(nr_mask);	

    AREA_LIST(area) {
	register u_int32 cur_id = ntohl(area->area_id);
	
	if (cur_id < area_id) {
	    continue;
	}

	RANGE_LIST(nr, area) {
	    u_int32 cur_net = ntohl(nr->nr_net);
	    u_int32 cur_mask = ntohl(nr->nr_mask);

	    if (next) {
		goto got_it;
	    }

	    if (cur_net < nr_net)
		continue;

	    if (cur_net == nr_net
		&& cur_mask == nr_mask) {
		if (isnext && len >= 2 * sizeof(struct in_addr) + 1) {
		    next = TRUE;
		} else {
		    goto got_it;
		}
	    } else if (cur_net > nr_net
		       || (cur_net == nr_net
			   && cur_mask > nr_mask)) {
		if (!isnext) {
		    nr = (struct NET_RANGE *) 0;
		}
		goto got_it;
	    }
	} RANGE_LIST_END(nr, area) ;
    } AREA_LIST_END(area) ;

    nr = (struct NET_RANGE *) 0;
    area = (struct AREA *) 0;

 got_it:
    *return_area = last_area = area;
    return last_nr = nr;
}


/*
 * var_ospfAreaAggregateTable: Callbacks for oid mib-2.ospf.14
 */
static u_char *
var_ospfAreaAggregateTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfAreaAggregateAreaID, ospfAreaAggregateLsdbType ospfAreaAggregateNet ospfAreaAggregateMask } */
/*=INDEX { ip, int, ip, ip } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + 1 + sizeof (struct in_addr) + sizeof (struct in_addr)))

    struct AREA *area;
    struct NET_RANGE *range;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(range = o_aggr_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE,
				    &area)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(range = o_aggr_lookup((u_int *)&name[vp->namelen], len, TRUE,&area)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(area->area_id, vp->namelen, name);
	name[vp->namelen + 4] = MIB_AGGR_SUMMARYLINK;
	put_ipaddr(range->nr_net, vp->namelen + 5, name);
	put_ipaddr(range->nr_mask, vp->namelen + 9, name);
	*length = vp->namelen + NDX_SIZE;
    }

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFAREAAGGREGATEAREAID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(area->area_id);

    case OSPFAREAAGGREGATELSDBTYPE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_AGGR_SUMMARYLINK);

    case OSPFAREAAGGREGATENET:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(range->nr_net);

    case OSPFAREAAGGREGATEMASK:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(range->nr_mask);

    case OSPFAREAAGGREGATESTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_VALID);

    case OSPFAREAAGGREGATEEFFECT:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER((range->nr_status == Advertise)
		     ? MIB_ADVERTISE_MATCHING : MIB_DONOT_ADVERTISE_MATCHING);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}

/**/

/* Host group */
static struct OSPF_HOSTS *
o_host_lookup (register unsigned int * ip, u_int len, int isnext)
{
    u_int32 host_addr = (u_int32) 0;
    register struct OSPF_HOSTS *host;
    register struct AREA *area;
    static unsigned int *last;
    static struct OSPF_HOSTS *last_host;

    if (snmp_last_match(&last, ip, len, isnext)) {
	return last_host;
    }

    oid2ipaddr(ip, &host_addr, len);

    if (len > sizeof(struct in_addr) && ip[sizeof (struct in_addr)]) {
	/* We don't support TOS */
	return last_host = (struct OSPF_HOSTS *) 0;
    }

    if (isnext) {
	register struct OSPF_HOSTS *new = (struct OSPF_HOSTS *) 0;
	u_int32 new_addr = 0;

	GNTOHL(host_addr);

	AREA_LIST(area) {

	    if (area->hostcnt) {
		host = &area->hosts;

		while ((host = host->ptr[NEXT])) {
		    u_int32 c_addr = ntohl(host->host_if_addr);

		    if ((c_addr > host_addr 
                        || c_addr == host_addr && len < sizeof(struct in_addr))
                       && (!new || c_addr < new_addr)) {
			new = host;
			new_addr = c_addr;
		    }
		}
	    }
	} AREA_LIST_END(area) ;

	return last_host = new;
    } else {

	AREA_LIST(area) {

	    if (area->hostcnt) {
		host = &area->hosts;

		while ((host = host->ptr[NEXT])) {
		    if (host_addr == ntohl(host->host_if_addr)) {
			return last_host = host;
		    }
		}
	    }
	} AREA_LIST_END(area) ;

	return last_host = (struct OSPF_HOSTS *) 0;
    }
}

/*
 * var_ospfHostTable: Callbacks for oid mib-2.ospf.6
 */
static u_char *
var_ospfHostTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfHostIpAddress, ospfHostTOS } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + 1))

    struct OSPF_HOSTS *host;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(host = o_host_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(host = o_host_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(host->host_if_addr, vp->namelen, name);
	name[vp->namelen + 4] = 0; /* no TOS support */
	*length = vp->namelen + NDX_SIZE;
    }


    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFHOSTIPADDRESS:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(host->host_if_addr);

    case OSPFHOSTTOS:
	/* C type INTEGER, MIB type INTEGER */
	/* No support for TOS */
	return O_INTEGER(0);

    case OSPFHOSTMETRIC:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(ntohl(host->host_cost));

    case OSPFHOSTSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_VALID);

    case OSPFHOSTAREAID:
	/* C type IPADDRESS, MIB type IpAddress */
/* $$$ not implemented in original. waiting for bug response from gated.org 
 *  o_host_lookup() would need to return "area" or just "area->area_id".
 */

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}
/**/
/* Interface group */

struct intf_entry {
    struct intf_entry *forw;
    struct intf_entry *back;
    u_int32 addr;
    int index;
    struct INTF *intf;
};

static struct intf_entry o_intf_list = {&o_intf_list, &o_intf_list };
static int o_intf_cnt;
static block_t o_intf_index;
static unsigned int *o_intf_last;

#define	MINTF_LIST(intfp) \
    for (intfp = o_intf_list.forw; intfp != &o_intf_list; intfp = intfp->forw)
#define	MINTF_LIST_END(intfp)	

void
o_intf_get ()
{
    register struct intf_entry *intfp;
    register struct AREA *area;

    /* Free the old list */
    MINTF_LIST(intfp) {
	register struct intf_entry *intfp2 = intfp->back;

	REMQUE(intfp);
	task_block_free(o_intf_index, (void_t) intfp);

	intfp = intfp2;
    } MINTF_LIST_END(intfp) ;

    snmp_last_free(&o_intf_last);
    o_intf_cnt = 0;

    AREA_LIST(area) {
	register struct INTF *intf;

	INTF_LIST(intf, area) {
	    register u_int32 intf_addr = ntohl(INTF_LCLADDR(intf));
	    register int intf_index;

	    if (BIT_TEST(intf->ifap->ifa_state, IFS_POINTOPOINT)
		&& intf->ifap->ifa_addrent_local->ifae_n_if > 1) {
		/* Set addressless index */

		intf_index = intf->ifap->ifa_link->ifl_index;
	    } else {
		intf_index = 0;
	    }
	    
	    MINTF_LIST(intfp) {
		if (intf_addr < intfp->addr
		    || (intf_addr == intfp->addr
			&& intf_index < intfp->index)) {
		    break;
		}
	    } MINTF_LIST_END(intfp) ;

	    INSQUE(task_block_alloc(o_intf_index), intfp->back);
	    intfp->back->intf = intf;
	    intfp->back->addr = intf_addr;
	    intfp->back->index = intf_index;
	    o_intf_cnt++;
	} INTF_LIST_END(intf, area) ;
    } AREA_LIST_END(area) ;

}


static struct intf_entry *
o_intf_lookup (register unsigned int * ip, u_int len, int isnext)
{
    static struct intf_entry *last_intfp;

    if (snmp_last_match(&o_intf_last, ip, len, isnext)) {
	return last_intfp;
    }
    
    if (!o_intf_cnt) {
	return last_intfp = (struct intf_entry *) 0;
    }
    
    if (len) {
	u_int32 intf_addr;
	int intf_index = 0;
	register struct intf_entry *intfp;

	oid2ipaddr(ip, &intf_addr, len);
	GNTOHL(intf_addr);

        if (len > sizeof(struct in_addr))
	    intf_index = ip[sizeof (struct in_addr)];

	MINTF_LIST(intfp) {
            u_int32 cur_addr = ntohl(intfp->addr);
	    if (cur_addr == intf_addr
		&& intfp->index == intf_index) {
		if (!isnext || len < sizeof(struct in_addr) + 1) {
		    return last_intfp = intfp;
		}
	    } else if (cur_addr > intf_addr
		       || (cur_addr == intf_addr
			   && intfp->index > intf_index)) {
		return last_intfp = isnext ? intfp : (struct intf_entry *) 0;
	    }
	} MINTF_LIST_END(ip) ;

	return last_intfp = (struct intf_entry *) 0;
    }

    return last_intfp = o_intf_list.forw;
}


static inline int
o_intf_state (struct INTF * s_intf)
{
    int state;

    switch (s_intf->state) {
    case IDOWN:
	state = I_STATE_DOWN;
	break;
	
    case ILOOPBACK:
	state = I_STATE_LOOPBACK;
	break;
	
    case IWAITING:
	state = I_STATE_WAITING;
	break;
	
    case IPOINT_TO_POINT:
	state = I_STATE_P2P;
	break;
	
    case IDr:
	state = I_STATE_DR;
	break;
	
    case IBACKUP:
	state = I_STATE_BDR;
	break;
	
    case IDrOTHER:
	state = I_STATE_DROTHER;
	break;

    default:
	state = -1;
    }

    return state;
}

/*
 * var_ospfIfTable: Callbacks for oid mib-2.ospf.7
 */
static u_char *
var_ospfIfTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfIfIpAddress, ospfAddressLessIf } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + 1))
    struct intf_entry *intfp;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(intfp = o_intf_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(intfp = o_intf_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(sock2ip(intfp->intf->ifap->ifa_addr_local),
		   vp->namelen, name);
	name[vp->namelen + 4] = intfp->index;
	*length = vp->namelen + NDX_SIZE;
    }


    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFIFIPADDRESS:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(intfp->intf->ifap->ifa_addr_local);

    case OSPFADDRESSLESSIF:
	/* C type INTEGER, MIB type INTEGER */
	/* All interfaces have addresses */
	return O_INTEGER(intfp->index);

    case OSPFIFAREAID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(intfp->intf->area->area_id);

    case OSPFIFTYPE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intfp->intf->type);

    case OSPFIFADMINSTAT:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(BIT_TEST(intfp->intf->flags, OSPF_INTFF_ENABLE)
			 ? MIB_ENABLED : MIB_DISABLED);

    case OSPFIFRTRPRIORITY:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intfp->intf->nbr.pri);

    case OSPFIFTRANSITDELAY:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intfp->intf->transdly);

    case OSPFIFRETRANSINTERVAL:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intfp->intf->retrans_timer);

    case OSPFIFHELLOINTERVAL:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intfp->intf->hello_timer);

    case OSPFIFRTRDEADINTERVAL:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intfp->intf->dead_timer);

    case OSPFIFPOLLINTERVAL:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intfp->intf->poll_timer);

    case OSPFIFSTATE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(o_intf_state(intfp->intf));

    case OSPFIFDESIGNATEDROUTER:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(intfp->intf->dr
			? intfp->intf->dr->nbr_addr : inet_addr_default);

    case OSPFIFBACKUPDESIGNATEDROUTER:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(intfp->intf->bdr
			? intfp->intf->bdr->nbr_addr : inet_addr_default);

    case OSPFIFEVENTS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(intfp->intf->events);

    case OSPFIFAUTHKEY:
	/* C type STRING, MIB type OctetString */
	/* When read, ospfIfAuthKey always returns an Octet String of length zero. */
	*var_len = 0;
	return return_buf;

    case OSPFIFSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_VALID);

    case OSPFIFMULTICASTFORWARDING:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_BLOCKED);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}


/* Metric group */
static struct intf_entry *
o_metric_lookup (register unsigned int * ip, u_int len, int isnext)
{

    if (len && ip[sizeof (struct in_addr) + 1]) {
	/* We dont' support TOS */
	return (struct intf_entry *) 0;
    }

    return o_intf_lookup(ip, len, isnext);
}


/*
 * var_ospfIfMetricTable: Callbacks for oid mib-2.ospf.8
 */
static u_char *
var_ospfIfMetricTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfIfMetricIpAddress, ospfIfMetricAddressLessIf, ospfIfMetricTOS } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + 1 + 1))
    struct intf_entry *intfp;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(intfp = o_metric_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(intfp = o_metric_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(sock2ip(intfp->intf->ifap->ifa_addr_local),
		   vp->namelen, name);
	name[vp->namelen + 4] = intfp->index;
	name[vp->namelen + 5] = 0; /* no TOS support */
	*length = vp->namelen + NDX_SIZE;
    }


    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFIFMETRICIPADDRESS:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(intfp->intf->ifap->ifa_addr_local);

    case OSPFIFMETRICADDRESSLESSIF:
	/* C type INTEGER, MIB type INTEGER */
	/* All interfaces have addresses */
	return O_INTEGER(intfp->index);

    case OSPFIFMETRICTOS:
	/* C type INTEGER, MIB type INTEGER */
	/* No support for TOS */
	return O_INTEGER(0);

    case OSPFIFMETRICVALUE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intfp->intf->cost);

    case OSPFIFMETRICSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_VALID);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}

/* Virtual Interfaces */

static struct intf_entry o_vintf_list = {&o_vintf_list, &o_vintf_list };
static int o_vintf_cnt;
static unsigned int *o_vintf_last;

#define	MVINTF_LIST(intfp)	for (intfp = o_vintf_list.forw; intfp != &o_vintf_list; intfp = intfp->forw)
#define	MVINTF_LIST_END(ip)	

void
o_vintf_get ()
{
    register struct intf_entry *intfp;
    register struct INTF *intf;

    /* Free the old list */
    MVINTF_LIST(intfp) {
	register struct intf_entry *intfp2 = intfp->back;

	REMQUE(intfp);
	task_block_free(o_intf_index, (void_t) intfp);

	intfp = intfp2;
    } MVINTF_LIST_END(intfp) ;

    o_vintf_cnt = 0;
    snmp_last_free(&o_vintf_last);

    VINTF_LIST(intf) {
	u_int32 intf_area = ntohl(intf->trans_area->area_id);
	u_int32 nbr_id = ntohl(NBR_ID(&intf->nbr));
	    
	MVINTF_LIST(intfp) {
	    if (intf_area <= ntohl(intfp->intf->trans_area->area_id) &
		nbr_id > ntohl(NBR_ID(&intfp->intf->nbr))) {
		break;
	    }
	} MVINTF_LIST_END(intfp) ;

	INSQUE(task_block_alloc(o_intf_index), intfp);
	intfp->forw->intf = intf;
	o_vintf_cnt++;
    } VINTF_LIST_END(intfp) ;
}


static struct INTF *
o_vintf_lookup (register unsigned int * ip, u_int len, int isnext)
{
    static struct INTF *last_intf;

    if (snmp_last_match(&o_vintf_last, ip, len, isnext)) {
	return last_intf;
    }
    
    if (!o_vintf_cnt) {
	return last_intf = (struct INTF *) 0;
    }
    
    if (len) {
	u_int32 area_id, nbr_id;
	register struct intf_entry *intfp;

	oid2ipaddr(ip, &area_id, len);
	GNTOHL(area_id);
	
        ip += sizeof(struct in_addr);
	oid2ipaddr(ip, &nbr_id, len - sizeof(struct in_addr));
	GNTOHL(nbr_id);

	MINTF_LIST(intfp) {
	    register u_int32 cur_area = ntohl(intfp->intf->trans_area->area_id);
	    register u_int32 cur_nbr = ntohl(NBR_ID(&intfp->intf->nbr));

	    if (cur_area == area_id) {
		if (nbr_id == cur_nbr) {
		    if (!isnext || len < 2 * sizeof(struct in_addr)) {
			return last_intf = intfp->intf;
		    }
		} else if (nbr_id > cur_nbr) {
		    continue;
		}
	    } if (cur_area < area_id) {
		continue;
	    }

	    return last_intf = isnext ? intfp->intf : (struct INTF *) 0;
	} MINTF_LIST_END(ip) ;

	return last_intf = (struct INTF *) 0;
    }

    return last_intf = o_vintf_list.forw->intf;
}


/* Virtual Interface group */
/*
 * var_ospfVirtIfTable: Callbacks for oid mib-2.ospf.9
 */
static u_char *
var_ospfVirtIfTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfVirtIfAreaId, ospfVirtIfNeighbor } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + sizeof (struct in_addr)))

    struct INTF *intf;
    int len;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(intf = o_vintf_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(intf = o_vintf_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(intf->trans_area->area_id, vp->namelen, name);
	put_ipaddr(NBR_ID(&intf->nbr), vp->namelen + 4, name);
	*length = vp->namelen + NDX_SIZE;
    }


    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFVIRTIFAREAID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(intf->trans_area->area_id);

    case OSPFVIRTIFNEIGHBOR:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(intf->nbr.nbr_id);

    case OSPFVIRTIFTRANSITDELAY:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intf->transdly);

    case OSPFVIRTIFRETRANSINTERVAL:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intf->retrans_timer);

    case OSPFVIRTIFHELLOINTERVAL:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intf->hello_timer);

    case OSPFVIRTIFRTRDEADINTERVAL:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(intf->dead_timer);

    case OSPFVIRTIFSTATE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(o_intf_state(intf));

    case OSPFVIRTIFEVENTS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(intf->events);

    case OSPFVIRTIFAUTHKEY:
	/* C type STRING, MIB type OctetString */
	/* When read, ospfIfAuthKey always returns an Octet String of length zero. */
	*var_len = 0;
	return return_buf;

    case OSPFVIRTIFSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(MIB_VALID);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}



/* Neighbor group */

struct nbr_entry {
    struct NBR *nbr;
    u_int32 addr;
    u_int index;
};

static struct nbr_entry *o_nbr_list;
static u_int o_nbr_cnt;
static u_int o_nbr_size;

static int
o_nbr_compare (const VOID_T p1, const VOID_T p2)
{
    register const struct nbr_entry *nbrp1 = (const struct nbr_entry *) p1;
    register const struct nbr_entry *nbrp2 = (const struct nbr_entry *) p2;

    if (nbrp1->addr == nbrp2->addr
	&& nbrp1->index == nbrp2->index) {
	return 0;
    } else if (nbrp1->addr < nbrp2->addr
	       || (nbrp1->addr == nbrp2->addr
		   && nbrp1->index < nbrp2->index)) {
	return -1;
    }

    return 1;
}


static void
o_nbr_get ()
{
    register struct nbr_entry *nbrp;
    register struct intf_entry *intfp;

    if (o_nbr_size < ospf.nbrcnt + ospf.nintf) {
	if (o_nbr_list) {
	    task_block_reclaim((size_t) (o_nbr_size * sizeof (*o_nbr_list)), (void_t) o_nbr_list);
	}

	o_nbr_size = ospf.nbrcnt + ospf.nintf;
	o_nbr_list = (struct nbr_entry *) task_block_malloc((size_t) (o_nbr_size * sizeof (*o_nbr_list)));
    }

    nbrp = o_nbr_list;
    o_nbr_cnt = 0;
    
    MINTF_LIST(intfp) {
	register struct NBR *nbr;

	NBRS_LIST(nbr, intfp->intf) {
	    assert(o_nbr_cnt <= o_nbr_size);
	    nbrp->nbr = nbr;
	    nbrp->addr = ntohl(NBR_ADDR(nbr));
	    if (BIT_TEST(nbr->intf->ifap->ifa_state, IFS_POINTOPOINT)
		&& nbr->intf->ifap->ifa_addrent_local->ifae_n_if > 1) {
		nbrp->index = nbr->intf->ifap->ifa_link->ifl_index;
	    } else {
		nbrp->index = 0;
	    }
	    nbrp++;
	} NBRS_LIST_END(nbr, intfp->intf) ;
    } MINTF_LIST_END(intfp) ;

    o_nbr_cnt = nbrp - o_nbr_list;

    qsort((caddr_t) o_nbr_list,
	  o_nbr_cnt,
	  sizeof (struct nbr_entry), 
	  o_nbr_compare);
}


static struct nbr_entry *
o_nbr_lookup (register unsigned int * ip, u_int len, int isnext)
{
    static struct nbr_entry *last_nbrp;
    static unsigned int *last;
    static int last_quantum;

    if (last_quantum != snmp_quantum) {
	last_quantum = snmp_quantum;

	o_nbr_get();

	if (last) {
	    task_mem_free((task *) 0, (void_t) last);
	    last = (unsigned int *) 0;
	}
    }

    if (snmp_last_match(&last, ip, len, isnext)) {
	return last_nbrp;
    }

    if (!o_nbr_cnt) {
	return last_nbrp = (struct nbr_entry *) 0;
    }
    
    if (len) {
	u_int32 nbr_addr;
	int nbr_index = 0;
	register struct nbr_entry *nbrp = o_nbr_list;
	struct nbr_entry *lp = &o_nbr_list[o_nbr_cnt];
	
	oid2ipaddr(ip, &nbr_addr, len);
	GNTOHL(nbr_addr);

        if (len > sizeof(struct in_addr))
	    nbr_index = ip[sizeof (struct in_addr)];

	do {
            u_int32 cur_addr = ntohl(nbrp->addr);
	    if (cur_addr == nbr_addr
		&& nbrp->index == nbr_index) {
		if (!isnext || len < sizeof (struct in_addr) + 1) {
		    return last_nbrp = nbrp;
		}
	    } else if (cur_addr > nbr_addr
		       || (cur_addr == nbr_addr
			   && nbrp->index > nbr_index)) {
		return last_nbrp = isnext ? nbrp : (struct nbr_entry *) 0;
	    }
	} while (++nbrp < lp) ;

	return last_nbrp = (struct nbr_entry *) 0;
    }

    return last_nbrp = o_nbr_list;
}


static inline int
o_nbr_state (struct NBR * s_nbr)
{
    int state;
    
    switch (s_nbr->state) {
    case NDOWN:
	state = N_STATE_DOWN;
	break;

    case NATTEMPT:
	state = N_STATE_ATTEMPT;
	break;
	
    case NINIT:
	state = N_STATE_INIT;
	break;
	
    case N2WAY:
	state = N_STATE_2WAY;
	break;
	
    case NEXSTART:
	state = N_STATE_EXSTART;
	break;
	
    case NEXCHANGE:
	state = N_STATE_EXCHANGE;
	break;
	
    case NLOADING:
	state = N_STATE_LOADING;
	break;

    case NFULL:
	state = N_STATE_FULL;
	break;

    default:
	state = -1;
	break;
    }

    return state;
}

/*
 * var_ospfNbrTable: Callbacks for oid mib-2.ospf.10
 */
static u_char *
var_ospfNbrTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfNbrIpAddr, ospfNbrAddressLessIndex } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + 1))

    struct nbr_entry *nbrp;
    int len, i;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(nbrp = o_nbr_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(nbrp = o_nbr_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(sock2ip(nbrp->nbr->nbr_addr), vp->namelen, name);
	name[vp->namelen + 4] = nbrp->index;
	*length = vp->namelen + NDX_SIZE;
    }



    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFNBRIPADDR:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(nbrp->nbr->nbr_addr);

    case OSPFNBRADDRESSLESSINDEX:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(nbrp->index);

    case OSPFNBRRTRID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(nbrp->nbr->nbr_id
			? nbrp->nbr->nbr_id : inet_addr_default);

    case OSPFNBROPTIONS:
	/* C type INTEGER, MIB type INTEGER */
	i = 0;

	if (!BIT_TEST(nbrp->nbr->intf->area->area_flags, OSPF_AREAF_STUB)) {
	    BIT_SET(i, MIB_BIT_ASE);
	}

	/* TOS not supported */
	return O_INTEGER(i);

    case OSPFNBRPRIORITY:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(nbrp->nbr->pri);

    case OSPFNBRSTATE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(o_nbr_state(nbrp->nbr));

    case OSPFNBREVENTS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(nbrp->nbr->events);

    case OSPFNBRLSRETRANSQLEN:
	/* C type GAUGE, MIB type Gauge */
	return O_INTEGER(nbrp->nbr->rtcnt);

    case OSPFNBMANBRSTATUS:
	/* C type INTEGER, MIB type INTEGER */
	if (nbrp->nbr->intf->type == NONBROADCAST)
	    return O_INTEGER(MIB_VALID);
	else
	    return NULL;

    case OSPFNBMANBRPERMANENCE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(nbrp->nbr->intf->type == NONBROADCAST
			 ? N_PERMANENCE_PERMANENT : N_PERMANENCE_DYNAMIC);	/* XXX - ??? */

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}

/* Virtual neighbor group */
/*
 * var_ospfVirtNbrTable: Callbacks for oid mib-2.ospf.11
 */
static u_char *
var_ospfVirtNbrTable(vp, name, length, exact, var_len, write_method)
    register struct variable *vp; /* IN- corresponding variable entry */
    oid *name;         /* IN/OUT- input name requested, output name found */
    int *length;       /* IN/OUT- length of input and output oid's */
    int  exact;        /* IN- TRUE if an exact match was requested */
    int *var_len;      /* OUT- length of variable or 0 if function returned */
    PWM *write_method; /* OUT- ptr to function to set variable, otherwise 0 */
{
/* INDEX { ospfVirtNbrArea, ospfVirtNbrRtrId } */
#define NDX_SIZE (int)(	(sizeof (struct in_addr) + sizeof (struct in_addr)))

    struct INTF *intf;
    int len, i;

    if (exact) {
	if (*length != vp->namelen + NDX_SIZE)
	    return NULL;		/* can not find it */

	if (!(intf = o_vintf_lookup((u_int *)&name[vp->namelen], NDX_SIZE, FALSE)))
	    return NULL;		/* can not find it */
    } else {
	
	if ((*length < vp->namelen)
	    || (compare_oid(name, vp->namelen, vp->name, vp->namelen) < 0)) {
	    len = 0;
	} else {
	    len = *length - vp->namelen;
	}
	if (!(intf = o_vintf_lookup((u_int *)&name[vp->namelen], len, TRUE)))
	    return NULL;		/* nothing to find */
	bcopy(vp->name, name, vp->namelen * sizeof(oid));
	put_ipaddr(intf->trans_area->area_id, vp->namelen, name);
	put_ipaddr(NBR_ID(&intf->nbr), vp->namelen + 4, name);
	*length = vp->namelen + NDX_SIZE;
    }

    *var_len = sizeof(int32_return); /* default length */

    switch (vp->magic) {
    case OSPFVIRTNBRAREA:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR_RAW(intf->trans_area->area_id);

    case OSPFVIRTNBRRTRID:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(intf->nbr.nbr_id
			? intf->nbr.nbr_id : inet_addr_default);

    case OSPFVIRTNBRIPADDR:
	/* C type IPADDRESS, MIB type IpAddress */
	return O_IPADDR(intf->nbr.nbr_id
			? intf->nbr.nbr_id : inet_addr_default);

    case OSPFVIRTNBROPTIONS:
	/* C type INTEGER, MIB type INTEGER */
	i = 0;
	
	if (!BIT_TEST(intf->area->area_flags, OSPF_AREAF_STUB)) {
	    BIT_SET(i, MIB_BIT_ASE);
	}

	/* TOS not supported */
	return O_INTEGER(i);


    case OSPFVIRTNBRSTATE:
	/* C type INTEGER, MIB type INTEGER */
	return O_INTEGER(o_nbr_state(&intf->nbr));

    case OSPFVIRTNBREVENTS:
	/* C type COUNTER, MIB type Counter */
	return O_INTEGER(intf->nbr.events);

    case OSPFVIRTNBRLSRETRANSQLEN:
	/* C type GAUGE, MIB type Gauge */
	return O_INTEGER(intf->nbr.dbcnt + intf->nbr.reqcnt + intf->nbr.rtcnt);

    default:
	/* The magic number is not valid */
	ERROR_MSG("");
    }
    return NULL;
#undef	NDX_SIZE
}


void init_ospf_vars()
{
    add_all_subtrees(ospf_subtrees,
		     sizeof(ospf_subtrees)/sizeof(struct subtree));
};


void
ospf_init_mib(enabled)
int enabled;
{
    if (enabled) {
	if (!o_intf_index) {
	    o_intf_index = task_block_init(sizeof (struct intf_entry),
					   "ospf_intf_entry");
	}
    } else {
	struct AREA *area;
	struct intf_entry *intfp;
	
	/* Free LSDB memory */
	AREA_LIST(area) {
	    int type;

	    for (type = LS_RTR; type < LS_ASE; type++) {
		if (area->mib_lsdb_size[type]) {
		    task_block_reclaim((size_t)((area->mib_lsdb_size[type] + 1)
						* sizeof (struct LSDB *)),
				       (void_t) area->mib_lsdb_list[type]);
		    area->mib_lsdb_list[type] = (struct LSDB **) 0;
		    area->mib_lsdb_cnt[type] = area->mib_lsdb_size[type] = 0;
		}
	    }
	} AREA_LIST_END(area) ;

	if (ospf.mib_ase_size) {
	    task_block_reclaim((size_t) ((ospf.mib_ase_size + 1)
					 * sizeof (struct LSDB *)),
			       (void_t) ospf.mib_ase_list);
	    ospf.mib_ase_cnt = ospf.mib_ase_size = 0;
	}

	/* Free Interface memory */
	MINTF_LIST(intfp) {
	    register struct intf_entry *intfp2 = intfp->back;

	    REMQUE(intfp);
	    task_block_free(o_intf_index, (void_t) intfp);

	    intfp = intfp2;
	} MINTF_LIST_END(intfp) ;

	MVINTF_LIST(intfp) {
	    register struct intf_entry *intfp2 = intfp->back;

	    REMQUE(intfp);
	    task_block_free(o_intf_index, (void_t) intfp);

	    intfp = intfp2;
	} MVINTF_LIST_END(intfp) ;

	/* Free neighbor memory */
	if (o_nbr_size) {
	    if (o_nbr_list) {
		task_block_reclaim((size_t)(o_nbr_size * sizeof (*o_nbr_list)),
				   (void_t)o_nbr_list);
	    }

	    o_nbr_size = o_nbr_cnt = 0;
	    o_nbr_list = (struct nbr_entry *) 0;
	}

    }
}
#endif	/* PROTO_OSPF && PROTO_CMU_SNMP */
