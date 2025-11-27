package com.learnsecurity;

import java.io.*;
import java.net.*;
import java.util.*;
import java.text.SimpleDateFormat;

public class SimpleWebServer {

    // Run the HTTP server on this TCP port.
    private static final int PORT = 8080;

    // The socket used to process incoming connections from web clients.
    private static ServerSocket dServerSocket;

    public SimpleWebServer() throws Exception {
        dServerSocket = new ServerSocket(PORT);
    }

    public void run() throws Exception {
        while (true) {
            // Wait for a connection from a client.
            final Socket s = dServerSocket.accept();

            // Then process the client's request in a new thread.
            new Thread(new Runnable() {
                public void run() {
                    try {
                        processRequest(s);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }).start();
        }
    }

    // Reads the HTTP request from the client, and responds with the file the user
    // requested or a HTTP error code.
    public void processRequest(Socket s) throws Exception {
        // Used to read data from the client.
        BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        // Used to write data to the client.
        OutputStreamWriter osw = new OutputStreamWriter(s.getOutputStream());

        String request = br.readLine();

        // Log the request
        log(s, request);

        String command = null;
        String pathname = null;

        // Parse the HTTP request.
        if (request == null)
            return;
        StringTokenizer st = new StringTokenizer(request, " ");
        if (st.countTokens() < 2)
            return;
        command = st.nextToken();
        pathname = st.nextToken();

        if (command.equals("GET")) {
            // If the request is a GET try to respond with the file the user is requesting.
            serveFile(osw, pathname);
        } else if (command.equals("PUT")) {
            storeFile(br, osw, pathname);
        } else {
            // if the request is a NOT a GET,
            // return an error saying this server does not implement the requested command
            osw.write("HTTP/1.0 501 Not Implemented\n\n");
        }

        // close the connection to the client
        osw.close();
    }

    public void serveFile(OutputStreamWriter osw, String pathname) throws Exception {
        FileReader fr = null;
        int c = -1;
        StringBuffer sb = new StringBuffer();
        // remove the initial slash at the beginning of the pathname in the request
        if (pathname.length() > 0 && pathname.charAt(0) == '/')
            pathname = pathname.substring(1);
        // if there was no filename specified by the client, serve the "index.html" file
        if (pathname.equals("/") || (pathname.length() == 0))
            pathname = "index.html";

        // Security check: Prevent directory traversal
        File f = new File(pathname);
        String canonicalPath = f.getCanonicalPath();
        String currentDir = new File(".").getCanonicalPath();

        if (!canonicalPath.startsWith(currentDir)) {
            osw.write("HTTP/1.0 403 Forbidden\n\n");
            return;
        }

        // try to open file specified by pathname
        try {
            fr = new FileReader(pathname);
            c = fr.read();
        } catch (Exception e) {
            // if the file is not found, return the appropriate HTTP response code
            osw.write("HTTP/1.0 404 Not Found\n\n");
            return;
        }
        // if the requested file can be successfully opened and read, then return an OK
        // response code and send the contents of the file
        osw.write("HTTP/1.0 200 OK\n\n");
        while (c != -1) {
            sb.append((char) c);
            c = fr.read();
        }
        osw.write(sb.toString());
    }

    private synchronized void log(Socket s, String request) {
        try {
            PrintWriter pw = new PrintWriter(new FileWriter("server.log", true));
            String ip = s.getInetAddress().getHostAddress();
            String time = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
            pw.println(time + " " + ip + " " + request);
            pw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void storeFile(BufferedReader br, OutputStreamWriter osw, String pathname) throws Exception {
        // Sanitize path
        if (pathname.length() > 0 && pathname.charAt(0) == '/')
            pathname = pathname.substring(1);
        if (pathname.equals("/") || (pathname.length() == 0))
            pathname = "index.html";

        File f = new File(pathname);
        String canonicalPath = f.getCanonicalPath();
        String currentDir = new File(".").getCanonicalPath();

        if (!canonicalPath.startsWith(currentDir)) {
            osw.write("HTTP/1.0 403 Forbidden\n\n");
            return;
        }

        // Read headers to find Content-Length
        String line;
        int contentLength = 0;
        while ((line = br.readLine()) != null && line.length() > 0) {
            if (line.startsWith("Content-Length:")) {
                try {
                    contentLength = Integer.parseInt(line.substring(15).trim());
                } catch (NumberFormatException e) {
                    // ignore
                }
            }
        }

        // Read body
        char[] buffer = new char[1024];
        int bytesRead = 0;
        int totalRead = 0;
        FileWriter fw = new FileWriter(pathname);

        if (contentLength > 0) {
            while (totalRead < contentLength) {
                int toRead = Math.min(buffer.length, contentLength - totalRead);
                bytesRead = br.read(buffer, 0, toRead);
                if (bytesRead == -1)
                    break;
                fw.write(buffer, 0, bytesRead);
                totalRead += bytesRead;
            }
        } else {
            // Fallback if no content length (not ideal but works for some simple clients
            // that close connection)
            while (br.ready() && (bytesRead = br.read(buffer)) != -1) {
                fw.write(buffer, 0, bytesRead);
            }
        }
        fw.close();
        osw.write("HTTP/1.0 201 Created\n\n");
    }

    // This method is called when the program is run from the command line.
    public static void main(String[] args) throws Exception {
        // Create a SimpleWebServer object, and run it
        SimpleWebServer sws = new SimpleWebServer();
        sws.run();
    }
}
