
/*------------------------------------------------------------------------
 * RttGetLocalIP  --  returns local IP address
 *------------------------------------------------------------------------
 */
u_int RttGetLocalIP()
{  
  char hn[40];
  struct hostent *hp;
  static u_int localIp = 0;

  if (localIp) {
    return localIp;
  }

  gethostname(hn, 40);
  hp = gethostbyname( hn );
  if( hp == 0 ) {
    return (RTTFAILED); 
  }

  localIp = ntohl(*((long *) hp->h_addr));

  return localIp;
}

/*------------------------------------------------------------------------
 * RttHostnameToIP  --  maps hostname to IP address
 *------------------------------------------------------------------------
 */
u_int RttHostnameToIP(char *hn) {
  struct hostent *hp;
  long addr;

  hp = gethostbyname( hn );
  if( hp == 0 ) {
    return (RTTFAILED); 
  }

  addr = ntohl(*((long *) hp->h_addr));

  return (u_int) addr;
}
