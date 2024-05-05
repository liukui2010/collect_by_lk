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

#include "../config.h"
#include <stdio.h>
#include <string.h>


int skip[1000] = {0};
char option[100][80];
int num_options=0;
char *optdir=NULL; /* directory containing default options */

int optionset(char *);
void read_options(void);

void
read_options(void)
{
   FILE *fp;
   char buff[1024], *str;

   /* Read in options from options file */
   fp = fopen("options", "r");
   if (!fp && optdir) {
      sprintf(buff, "%s/options", optdir);
      fp = fopen(buff, "r");
   }
   if (!fp)
      return;
   while (fgets(buff, sizeof(buff), fp) != NULL) {
      if (buff[0]=='#')
          continue; /* skip comments */
      for (str = strtok(buff, " \t\n\r"); str; str=strtok(NULL, " \t\n\r"))
         strcpy(option[num_options++], str);
   }
   fclose(fp);

   /* Process option dependencies from options.dep */
   fp = fopen("options.dep", "r");
   if (!fp && optdir) {
      sprintf(buff, "%s/options.dep", optdir);
      fp = fopen(buff, "r");
   }
   if (!fp)
      return;
   while (fgets(buff, sizeof(buff), fp) != NULL) {
      if (buff[0]=='#')
          continue; /* skip comments */

      /* See if target is set */
      str = strtok(buff, " :\t\n\r");
      if (!optionset(str))
         continue;

      /* If so, assert all prerequisites */
      for (; str; str=strtok(NULL, " :\t\n\r")) {
         if (!optionset(str))
            strcpy(option[num_options++], str);
      }
   }
   fclose(fp);
}

int 
optionset(char *str)
{
   int i;

   for (i=0; i<num_options; i++)
      if (!strcasecmp(option[i], str))
         return 1;
   return 0;
}

int
main(int argc, char **argv)
{
   char buff[1024], *word;
   FILE *fin  = stdin;
   FILE *fout = stdout;
   int level=0;

   if (argc>1)
      optdir = argv[1];

   read_options();

   while (fgets(buff, sizeof(buff), fin) != NULL) {
      if (!strncmp(buff, "@BEGIN:", 7)) {
         level++;
         skip[level] = skip[level-1];
         if (!skip[level]) {
            word = strtok(buff+7, " \t\n\r");
            if (word) {
               if (!strcasecmp(word, "NOT")) {
                  word = strtok(NULL, " \t\n\r");
                  if (optionset(word))
                     skip[level]=1;
               } else if (!optionset(word))
                  skip[level]=1;
            }
         }
      } else if (!strncmp(buff, "@END:", 5)) {
         if (level>0)
            level--;
      } else if (!skip[level]) {
         fputs(buff, fout);
      }
   }
   exit(0);
}

